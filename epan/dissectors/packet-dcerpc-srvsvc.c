/* DO NOT EDIT
	This filter was automatically generated
	from srvsvc.idl and srvsvc.cnf.

	Pidl is a perl based IDL compiler for DCE/RPC idl files.
	It is maintained by the Samba team, not the Wireshark team.
	Instructions on how to download and install Pidl can be
	found at http://wiki.wireshark.org/Pidl

	$Id$
*/


#include "config.h"

#ifdef _MSC_VER
#pragma warning(disable:4005)
#pragma warning(disable:4013)
#pragma warning(disable:4018)
#pragma warning(disable:4101)
#endif

#include <glib.h>
#include <string.h>
#include <epan/packet.h>

#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"
#include "packet-windows-common.h"
#include "packet-dcerpc-srvsvc.h"

/* Ett declarations */
static gint ett_dcerpc_srvsvc = -1;
static gint ett_srvsvc_srvsvc_NetCharDevInfo0 = -1;
static gint ett_srvsvc_srvsvc_NetCharDevCtr0 = -1;
static gint ett_srvsvc_srvsvc_NetCharDevInfo1 = -1;
static gint ett_srvsvc_srvsvc_NetCharDevCtr1 = -1;
static gint ett_srvsvc_srvsvc_NetCharDevInfo = -1;
static gint ett_srvsvc_srvsvc_NetCharDevCtr = -1;
static gint ett_srvsvc_srvsvc_NetCharDevQInfo0 = -1;
static gint ett_srvsvc_srvsvc_NetCharDevQCtr0 = -1;
static gint ett_srvsvc_srvsvc_NetCharDevQInfo1 = -1;
static gint ett_srvsvc_srvsvc_NetCharDevQCtr1 = -1;
static gint ett_srvsvc_srvsvc_NetCharDevQInfo = -1;
static gint ett_srvsvc_srvsvc_NetCharDevQCtr = -1;
static gint ett_srvsvc_srvsvc_NetConnInfo0 = -1;
static gint ett_srvsvc_srvsvc_NetConnCtr0 = -1;
static gint ett_srvsvc_srvsvc_NetConnInfo1 = -1;
static gint ett_srvsvc_srvsvc_NetConnCtr1 = -1;
static gint ett_srvsvc_srvsvc_NetConnCtr = -1;
static gint ett_srvsvc_srvsvc_NetFileInfo2 = -1;
static gint ett_srvsvc_srvsvc_NetFileCtr2 = -1;
static gint ett_srvsvc_srvsvc_NetFileInfo3 = -1;
static gint ett_srvsvc_srvsvc_NetFileCtr3 = -1;
static gint ett_srvsvc_srvsvc_NetFileInfo = -1;
static gint ett_srvsvc_srvsvc_NetFileCtr = -1;
static gint ett_srvsvc_srvsvc_SessionUserFlags = -1;
static gint ett_srvsvc_srvsvc_NetSessInfo0 = -1;
static gint ett_srvsvc_srvsvc_NetSessCtr0 = -1;
static gint ett_srvsvc_srvsvc_NetSessInfo1 = -1;
static gint ett_srvsvc_srvsvc_NetSessCtr1 = -1;
static gint ett_srvsvc_srvsvc_NetSessInfo2 = -1;
static gint ett_srvsvc_srvsvc_NetSessCtr2 = -1;
static gint ett_srvsvc_srvsvc_NetSessInfo10 = -1;
static gint ett_srvsvc_srvsvc_NetSessCtr10 = -1;
static gint ett_srvsvc_srvsvc_NetSessInfo502 = -1;
static gint ett_srvsvc_srvsvc_NetSessCtr502 = -1;
static gint ett_srvsvc_srvsvc_NetSessCtr = -1;
static gint ett_srvsvc_srvsvc_NetShareInfo0 = -1;
static gint ett_srvsvc_srvsvc_NetShareInfo1 = -1;
static gint ett_srvsvc_srvsvc_NetShareInfo2 = -1;
static gint ett_srvsvc_srvsvc_NetShareInfo501 = -1;
static gint ett_srvsvc_srvsvc_NetShareInfo502 = -1;
static gint ett_srvsvc_srvsvc_NetShareInfo1004 = -1;
static gint ett_srvsvc_srvsvc_NetShareInfo1006 = -1;
static gint ett_srvsvc_srvsvc_DFSFlags = -1;
static gint ett_srvsvc_srvsvc_NetShareCtr0 = -1;
static gint ett_srvsvc_srvsvc_NetShareCtr1 = -1;
static gint ett_srvsvc_srvsvc_NetShareCtr2 = -1;
static gint ett_srvsvc_srvsvc_NetShareCtr501 = -1;
static gint ett_srvsvc_srvsvc_NetShareCtr502 = -1;
static gint ett_srvsvc_srvsvc_NetShareCtr1004 = -1;
static gint ett_srvsvc_srvsvc_NetShareInfo1005 = -1;
static gint ett_srvsvc_srvsvc_NetShareCtr1005 = -1;
static gint ett_srvsvc_srvsvc_NetShareCtr1006 = -1;
static gint ett_srvsvc_srvsvc_NetShareInfo1007 = -1;
static gint ett_srvsvc_srvsvc_NetShareCtr1007 = -1;
static gint ett_srvsvc_srvsvc_NetShareCtr1501 = -1;
static gint ett_srvsvc_srvsvc_NetShareInfo = -1;
static gint ett_srvsvc_srvsvc_NetShareCtr = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo100 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo101 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo102 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo402 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo403 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo502 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo503 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo599 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1005 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1010 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1016 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1017 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1018 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1107 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1501 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1502 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1503 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1506 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1509 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1510 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1511 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1512 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1513 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1514 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1515 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1516 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1518 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1520 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1521 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1522 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1523 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1524 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1525 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1528 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1529 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1530 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1533 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1534 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1535 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1536 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1537 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1538 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1539 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1540 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1541 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1542 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1543 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1544 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1545 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1546 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1547 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1548 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1549 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1550 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1552 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1553 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1554 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1555 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo1556 = -1;
static gint ett_srvsvc_srvsvc_NetSrvInfo = -1;
static gint ett_srvsvc_srvsvc_NetDiskInfo0 = -1;
static gint ett_srvsvc_srvsvc_NetDiskInfo = -1;
static gint ett_srvsvc_srvsvc_Statistics = -1;
static gint ett_srvsvc_srvsvc_NetTransportInfo0 = -1;
static gint ett_srvsvc_srvsvc_NetTransportCtr0 = -1;
static gint ett_srvsvc_srvsvc_NetTransportInfo1 = -1;
static gint ett_srvsvc_srvsvc_NetTransportCtr1 = -1;
static gint ett_srvsvc_srvsvc_TransportFlags = -1;
static gint ett_srvsvc_srvsvc_NetTransportInfo2 = -1;
static gint ett_srvsvc_srvsvc_NetTransportCtr2 = -1;
static gint ett_srvsvc_srvsvc_NetTransportInfo3 = -1;
static gint ett_srvsvc_srvsvc_NetTransportCtr3 = -1;
static gint ett_srvsvc_srvsvc_NetTransportCtr = -1;
static gint ett_srvsvc_srvsvc_NetRemoteTODInfo = -1;
static gint ett_srvsvc_srvsvc_NetTransportInfo = -1;


/* Header field declarations */
static gint hf_srvsvc_srvsvc_NetDiskInfo0_disk = -1;
static gint hf_srvsvc_srvsvc_NetConnInfo1_user = -1;
static gint hf_srvsvc_srvsvc_DFSFlags_SHARE_1005_FLAGS_DFS_ROOT = -1;
static gint hf_srvsvc_srvsvc_NetTransportCtr1_count = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1536 = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo_info502 = -1;
static gint hf_srvsvc_srvsvc_NetFileEnum_resume_handle = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_threadcountadd = -1;
static gint hf_srvsvc_srvsvc_NetRemoteTODInfo_hunds = -1;
static gint hf_srvsvc_srvsvc_NetShareAdd_level = -1;
static gint hf_srvsvc_srvsvc_NetShareDelCommit_hnd = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_networkerrortreshold = -1;
static gint hf_srvsvc_srvsvc_NetServerTransportAddEx_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_maxkeepcomplsearch = -1;
static gint hf_srvsvc_srvsvc_NetDiskEnum_maxlen = -1;
static gint hf_srvsvc_srvsvc_NetRemoteTODInfo_mins = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_accessalert = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo_info0 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_initsesstable = -1;
static gint hf_srvsvc_srvsvc_NetSessInfo1_num_open = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1509_maxrawbuflen = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_sesssvc = -1;
static gint hf_srvsvc_srvsvc_NetSessEnum_level = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr_ctr1007 = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQCtr1_count = -1;
static gint hf_srvsvc_srvsvc_NetShareSetInfo_share_name = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr1501_count = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo3_vcs = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_minfreeconnections = -1;
static gint hf_srvsvc_srvsvc_NetPRNameCompare_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_maxfreeconnections = -1;
static gint hf_srvsvc_srvsvc_Statistics_bytessent_low = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1529 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_alertsched = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_numfiletasks = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_diskspacetreshold = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo102_announce = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_accessalert = -1;
static gint hf_srvsvc_srvsvc_NetSessInfo502_transport = -1;
static gint hf_srvsvc_srvsvc_NetShareEnum_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetTransportCtr1_array = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo_info1501 = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo3_name = -1;
static gint hf_srvsvc_srvsvc_NetFileClose_fid = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_auditedevents = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1554_linkinfovalidtime = -1;
static gint hf_srvsvc_srvsvc_NetSessInfo2_user_flags = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_maxlinkdelay = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_eroralert = -1;
static gint hf_srvsvc_srvsvc_NetSessCtr2_count = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1540_enablesharednetdrives = -1;
static gint hf_srvsvc_srvsvc_NetFileInfo_info3 = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo2_comment = -1;
static gint hf_srvsvc_srvsvc_Statistics_start = -1;
static gint hf_srvsvc_srvsvc_NetShareEnumAll_totalentries = -1;
static gint hf_srvsvc_srvsvc_NetSessInfo502_user = -1;
static gint hf_srvsvc_srvsvc_NetTransportEnum_level = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_numfiletasks = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQGetInfo_queue_name = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_sessconns = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_sesssvc = -1;
static gint hf_srvsvc_srvsvc_NetCharDevInfo_info1 = -1;
static gint hf_srvsvc_srvsvc_NetGetFileSecurity_sd_buf = -1;
static gint hf_srvsvc_srvsvc_NetConnInfo0_conn_id = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_maxmpxct = -1;
static gint hf_srvsvc_srvsvc_NetFileEnum_ctr = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo502_sessconns = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_rawworkitems = -1;
static gint hf_srvsvc_srvsvc_NetShareEnumAll_max_buffer = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_minrcvqueue = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo_info1 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_threadcountadd = -1;
static gint hf_srvsvc_srvsvc_NetFileInfo3_user = -1;
static gint hf_srvsvc_srvsvc_NetRemoteTODInfo_weekday = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo3_addr_len = -1;
static gint hf_srvsvc_srvsvc_Statistics_bytesrcvd_low = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1549_networkerrortreshold = -1;
static gint hf_srvsvc_srvsvc_NetServerSetServiceBitsEx_servicebitsofinterest = -1;
static gint hf_srvsvc_srvsvc_NetTransportEnum_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1542_maxfreeconnections = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_enableoplockforceclose = -1;
static gint hf_srvsvc_srvsvc_NetSrvGetInfo_info = -1;
static gint hf_srvsvc_srvsvc_NetNameValidate_name = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1511 = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr_ctr501 = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo0_addr = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_opensearch = -1;
static gint hf_srvsvc_srvsvc_NetFileCtr3_array = -1;
static gint hf_srvsvc_srvsvc_NetSessCtr_ctr0 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1552_maxlinkdelay = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_maxkeepcomplsearch = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_enablefcbopens = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo102_version_minor = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1501 = -1;
static gint hf_srvsvc_srvsvc_NetDiskEnum_totalentries = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1107 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1520 = -1;
static gint hf_srvsvc_srvsvc_NetCharDevInfo_info0 = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo1006_max_users = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_openfiles = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQEnum_level = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo502_rawworkitems = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_oplockbreakresponsewait = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQEnum_totalentries = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo3_password = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info502 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_initworkitems = -1;
static gint hf_srvsvc_srvsvc_NetTransportAdd_level = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo502_timesource = -1;
static gint hf_srvsvc_srvsvc_NetFileEnum_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetSetServiceBits_updateimmediately = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1537 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1534 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1525_maxkeepcomplsearch = -1;
static gint hf_srvsvc_srvsvc_NetFileCtr3_count = -1;
static gint hf_srvsvc_srvsvc_NetShareCheck_device_name = -1;
static gint hf_srvsvc_srvsvc_NetFileEnum_totalentries = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1528 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_scavtimeout = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_guestaccount = -1;
static gint hf_srvsvc_srvsvc_NetShareEnum_resume_handle = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1538_enablefcbopens = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_alist_mtime = -1;
static gint hf_srvsvc_srvsvc_NetTransportCtr0_count = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_alertsched = -1;
static gint hf_srvsvc_srvsvc_NetFileEnum_level = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1529_minrcvqueue = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo3_transport_flags = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_erroralert = -1;
static gint hf_srvsvc_srvsvc_NetConnInfo1_share = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info599 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_maxcopywritelen = -1;
static gint hf_srvsvc_srvsvc_NetShareSetInfo_info = -1;
static gint hf_srvsvc_srvsvc_NetSessInfo502_num_open = -1;
static gint hf_srvsvc_srvsvc_NetGetFileSecurity_share = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_enablesharednetdrives = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_maxcopyreadlen = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1509 = -1;
static gint hf_srvsvc_srvsvc_NetSessInfo1_client = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1540 = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo1005_dfs_flags = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_sessusers = -1;
static gint hf_srvsvc_srvsvc_NetCharDevInfo0_device = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo502_sd = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo3_domain = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_chdevjobs = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_threadpriority = -1;
static gint hf_srvsvc_srvsvc_NetCharDevCtr1_count = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1017_announce = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_maxpagedmemoryusage = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_guestaccount = -1;
static gint hf_srvsvc_srvsvc_NetSessInfo502_client = -1;
static gint hf_srvsvc_srvsvc_NetShareDel_share_name = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_maxmpxct = -1;
static gint hf_srvsvc_srvsvc_NetCharDevCtr0_array = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_alerts = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_maxpagedmemoryusage = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo101_comment = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1556_maxworkitemidletime = -1;
static gint hf_srvsvc_srvsvc_NetShareDelStart_hnd = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info403 = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo501_csc_policy = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo1_addr_len = -1;
static gint hf_srvsvc_srvsvc_NetSetServiceBits_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_srvheuristics = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo102_version_major = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr_ctr1004 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1510 = -1;
static gint hf_srvsvc_srvsvc_NetFileInfo_info2 = -1;
static gint hf_srvsvc_srvsvc_NetSrvGetInfo_level = -1;
static gint hf_srvsvc_srvsvc_NetShareDelSticky_share_name = -1;
static gint hf_srvsvc_srvsvc_NetConnEnum_totalentries = -1;
static gint hf_srvsvc_srvsvc_TransportFlags_SVTI2_REMAP_PIPE_NAMES = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr501_count = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_enableoplockforceclose = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo2_vcs = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo502_lmannounce = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo502_irpstacksize = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1018_anndelta = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_diskalert = -1;
static gint hf_srvsvc_srvsvc_NetFileGetInfo_fid = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1544_initconntable = -1;
static gint hf_srvsvc_srvsvc_NetTransportAdd_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetShareDelStart_reserved = -1;
static gint hf_srvsvc_srvsvc_NetNameValidate_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQCtr1_array = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo501_type = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr1_array = -1;
static gint hf_srvsvc_srvsvc_NetConnEnum_max_buffer = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_minfreeworkitems = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo502_initworkitems = -1;
static gint hf_srvsvc_srvsvc_NetGetFileSecurity_securityinformation = -1;
static gint hf_srvsvc_srvsvc_NetConnEnum_level = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo2_permissions = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1555_scavqosinfoupdatetime = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_minfreeconnections = -1;
static gint hf_srvsvc_srvsvc_NetRemoteTODInfo_elapsed = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_maxaudits = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_timesource = -1;
static gint hf_srvsvc_srvsvc_NetSessDel_client = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_chdevjobs = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo0_name = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQSetInfo_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1534_oplockbreakwait = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo_info0 = -1;
static gint hf_srvsvc_srvsvc_NetRemoteTODInfo_secs = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo1007_flags = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_minkeepcomplsearch = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQEnum_user = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQInfo1_priority = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo0_name = -1;
static gint hf_srvsvc_srvsvc_NetTransportCtr2_count = -1;
static gint hf_srvsvc_srvsvc_NetRemoteTOD_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo0_addr_len = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_maxcopyreadlen = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQInfo0_device = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo502_sesssvc = -1;
static gint hf_srvsvc_srvsvc_DFSFlags_CSC_CACHE_VDO = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr1501_array = -1;
static gint hf_srvsvc_srvsvc_NetShareSetInfo_parm_error = -1;
static gint hf_srvsvc_srvsvc_NetShareEnumAll_ctr = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo102_platform_id = -1;
static gint hf_srvsvc_srvsvc_NetSessCtr_ctr10 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo101_version_minor = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQSetInfo_parm_error = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1550_diskspacetreshold = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_enableoplocks = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr501_array = -1;
static gint hf_srvsvc_srvsvc_NetShareDel_reserved = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_acceptdownlevelapis = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_security = -1;
static gint hf_srvsvc_srvsvc_NetConnInfo1_conn_id = -1;
static gint hf_srvsvc_srvsvc_NetSessInfo502_user_flags = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1502 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1541_minfreeconnections = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_linkinfovalidtime = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_sessreqs = -1;
static gint hf_srvsvc_srvsvc_NetShareAdd_parm_error = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info100 = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr502_count = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1514_enablesoftcompat = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_minlinkthroughput = -1;
static gint hf_srvsvc_srvsvc_SessionUserFlags_SESS_NOENCRYPTION = -1;
static gint hf_srvsvc_srvsvc_NetServerSetServiceBitsEx_updateimmediately = -1;
static gint hf_srvsvc_srvsvc_NetConnInfo1_conn_time = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1543_initsesstable = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_xactmemsize = -1;
static gint hf_srvsvc_srvsvc_NetCharDevGetInfo_level = -1;
static gint hf_srvsvc_srvsvc_DFSFlags_FLAGS_FORCE_SHARED_DELETE = -1;
static gint hf_srvsvc_srvsvc_Statistics_stimeouts = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_sessopen = -1;
static gint hf_srvsvc_srvsvc_Statistics_bytessent_high = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo1_domain = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo1007_alternate_directory_name = -1;
static gint hf_srvsvc_srvsvc_NetConnCtr0_count = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_minkeepsearch = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_acceptdownlevelapis = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr2_array = -1;
static gint hf_srvsvc_srvsvc_NetGetFileSecurity_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo502_maxpagedmemoryusage = -1;
static gint hf_srvsvc_srvsvc_NetSessInfo10_client = -1;
static gint hf_srvsvc_srvsvc_NetTransportCtr_ctr0 = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQPurge_queue_name = -1;
static gint hf_srvsvc_srvsvc_Statistics_jobsqueued = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1550 = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo_info1007 = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQGetInfo_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1513 = -1;
static gint hf_srvsvc_srvsvc_NetSetFileSecurity_file = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_activelocks = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo2_addr = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo102_anndelta = -1;
static gint hf_srvsvc_srvsvc_NetFileGetInfo_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_threadpriority = -1;
static gint hf_srvsvc_srvsvc_NetSessInfo502_idle_time = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1537_enableoplockforceclose = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_maxnonpagedmemoryusage = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_opensearch = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_enableforcedlogoff = -1;
static gint hf_srvsvc_srvsvc_NetSrvSetInfo_parm_error = -1;
static gint hf_srvsvc_srvsvc_NetShareEnumAll_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_glist_mtime = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo502_comment = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1552 = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr1004_count = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_minkeepcomplsearch = -1;
static gint hf_srvsvc_srvsvc_NetConnInfo1_conn_type = -1;
static gint hf_srvsvc_srvsvc_NetRemoteTODInfo_year = -1;
static gint hf_srvsvc_srvsvc_NetTransportCtr_ctr1 = -1;
static gint hf_srvsvc_srvsvc_NetFileInfo2_fid = -1;
static gint hf_srvsvc_srvsvc_NetCharDevInfo1_time = -1;
static gint hf_srvsvc_srvsvc_NetShareEnum_ctr = -1;
static gint hf_srvsvc_srvsvc_NetPathCanonicalize_prefix = -1;
static gint hf_srvsvc_srvsvc_Statistics_syserrors = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr_ctr0 = -1;
static gint hf_srvsvc_srvsvc_NetPathCanonicalize_path = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQSetInfo_level = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQInfo1_device = -1;
static gint hf_srvsvc_srvsvc_NetSetServiceBits_servicebits = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1522_minkeepsearch = -1;
static gint hf_srvsvc_srvsvc_NetSessInfo1_idle_time = -1;
static gint hf_srvsvc_srvsvc_NetPathCanonicalize_pathflags = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_logonalert = -1;
static gint hf_srvsvc_srvsvc_NetShareGetInfo_info = -1;
static gint hf_srvsvc_srvsvc_NetDiskEnum_level = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_minfreeworkitems = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_connections = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQCtr_ctr1 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_maxfreeconnections = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_lanmask = -1;
static gint hf_srvsvc_srvsvc_NetShareEnum_totalentries = -1;
static gint hf_srvsvc_srvsvc_NetSessInfo10_idle_time = -1;
static gint hf_srvsvc_srvsvc_NetSetServiceBits_transport = -1;
static gint hf_srvsvc_srvsvc_NetServerSetServiceBitsEx_emulated_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetRemoteTODInfo_tinterval = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1536_enableoplocks = -1;
static gint hf_srvsvc_srvsvc_NetRemoteTODInfo_hours = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQInfo1_num_ahead = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_timesource = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_domain = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_opensearch = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr_ctr1006 = -1;
static gint hf_srvsvc_srvsvc_NetShareEnum_level = -1;
static gint hf_srvsvc_srvsvc_NetTransportEnum_max_buffer = -1;
static gint hf_srvsvc_srvsvc_NetShareAdd_info = -1;
static gint hf_srvsvc_srvsvc_NetTransportCtr0_array = -1;
static gint hf_srvsvc_srvsvc_NetConnCtr_ctr1 = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQSetInfo_queue_name = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo100_server_name = -1;
static gint hf_srvsvc_srvsvc_NetShareEnum_max_buffer = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1535 = -1;
static gint hf_srvsvc_srvsvc_NetSessInfo1_time = -1;
static gint hf_srvsvc_srvsvc_NetSetFileSecurity_sd_buf = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1521 = -1;
static gint hf_srvsvc_srvsvc_NetShareGetInfo_level = -1;
static gint hf_srvsvc_srvsvc_NetShareEnumAll_level = -1;
static gint hf_srvsvc_srvsvc_NetSessInfo10_time = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr1004_array = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1502_sessvcs = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_numadmin = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1548_errortreshold = -1;
static gint hf_srvsvc_srvsvc_NetDiskInfo_disks = -1;
static gint hf_srvsvc_srvsvc_NetSessCtr10_array = -1;
static gint hf_srvsvc_opnum = -1;
static gint hf_srvsvc_srvsvc_NetConnCtr1_array = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr1006_count = -1;
static gint hf_srvsvc_srvsvc_NetShareCheck_type = -1;
static gint hf_srvsvc_srvsvc_NetSrvGetInfo_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr0_array = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_diskalert = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo102_server_type = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1542 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1512 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1503 = -1;
static gint hf_srvsvc_srvsvc_NetSessEnum_client = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr1_count = -1;
static gint hf_srvsvc_srvsvc_NetConnCtr0_array = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo2_transport_flags = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr_ctr502 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_ulist_mtime = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo_info1006 = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo1_type = -1;
static gint hf_srvsvc_srvsvc_NetCharDevEnum_totalentries = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_shares = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1016_hidden = -1;
static gint hf_srvsvc_srvsvc_NetSessInfo1_user = -1;
static gint hf_srvsvc_srvsvc_NetFileGetInfo_level = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1543 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_maxrawbuflen = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_opensearch = -1;
static gint hf_srvsvc_srvsvc_NetDiskEnum_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQEnum_resume_handle = -1;
static gint hf_srvsvc_srvsvc_NetSessInfo2_client = -1;
static gint hf_srvsvc_srvsvc_NetSessCtr2_array = -1;
static gint hf_srvsvc_srvsvc_NetSessDel_user = -1;
static gint hf_srvsvc_srvsvc_NetTransportCtr3_count = -1;
static gint hf_srvsvc_srvsvc_NetSrvSetInfo_info = -1;
static gint hf_srvsvc_srvsvc_Statistics_serrorout = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1005_comment = -1;
static gint hf_srvsvc_srvsvc_Statistics_sopens = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1544 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1010 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1515 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_numbigbufs = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo3_addr = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1511_sesscons = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1545_initfiletable = -1;
static gint hf_srvsvc_srvsvc_NetSetFileSecurity_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo502_acceptdownlevelapis = -1;
static gint hf_srvsvc_srvsvc_NetGetFileSecurity_file = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_ulist_mtime = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1522 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo101_version_major = -1;
static gint hf_srvsvc_srvsvc_NetNameValidate_name_type = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_scavqosinfoupdatetime = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_enablesoftcompat = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_xactmemsize = -1;
static gint hf_srvsvc_srvsvc_NetShareGetInfo_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetPRNameCompare_name2 = -1;
static gint hf_srvsvc_srvsvc_NetSessInfo502_time = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_maxrawbuflen = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_oplockbreakwait = -1;
static gint hf_srvsvc_srvsvc_NetShareDelSticky_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1524 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_maxaudits = -1;
static gint hf_srvsvc_srvsvc_NetDiskEnum_info = -1;
static gint hf_srvsvc_srvsvc_NetFileCtr_ctr2 = -1;
static gint hf_srvsvc_srvsvc_NetSetFileSecurity_securityinformation = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo_info2 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1525 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1539_enableraw = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_alist_mtime = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1515_enableforcedlogoff = -1;
static gint hf_srvsvc_srvsvc_NetCharDevGetInfo_device_name = -1;
static gint hf_srvsvc_srvsvc_NetFileCtr2_array = -1;
static gint hf_srvsvc_srvsvc_NetSessEnum_ctr = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1516 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo102_licenses = -1;
static gint hf_srvsvc_srvsvc_NetConnEnum_resume_handle = -1;
static gint hf_srvsvc_srvsvc_NetConnCtr_ctr0 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo101_platform_id = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_chdevs = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_maxnonpagedmemoryusage = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_domain = -1;
static gint hf_srvsvc_srvsvc_NetPathCanonicalize_pathtype = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_sizereqbufs = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1018 = -1;
static gint hf_srvsvc_srvsvc_NetCharDevInfo1_device = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_openfiles = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo0_net_addr = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_shares = -1;
static gint hf_srvsvc_srvsvc_Statistics_pwerrors = -1;
static gint hf_srvsvc_srvsvc_NetCharDevEnum_ctr = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1512_maxnonpagedmemoryusage = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1533 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo502_maxworkitems = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1549 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_numlockthreads = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info101 = -1;
static gint hf_srvsvc_srvsvc_NetPathCompare_pathtype = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo_info1005 = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr1007_count = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1005 = -1;
static gint hf_srvsvc_srvsvc_NetPathType_pathflags = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_oplockbreakwait = -1;
static gint hf_srvsvc_srvsvc_NetCharDevCtr1_array = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQCtr0_array = -1;
static gint hf_srvsvc_srvsvc_NetServerTransportAddEx_info = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQEnum_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetFileCtr2_count = -1;
static gint hf_srvsvc_srvsvc_NetPathCompare_pathflags = -1;
static gint hf_srvsvc_srvsvc_NetShareDelStart_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetConnInfo1_num_open = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo501_name = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo_info501 = -1;
static gint hf_srvsvc_srvsvc_NetPathCompare_path2 = -1;
static gint hf_srvsvc_srvsvc_NetShareAdd_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo502_maxnonpagedmemoryusage = -1;
static gint hf_srvsvc_srvsvc_NetSessInfo2_client_type = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1554 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_maxworkitemidletime = -1;
static gint hf_srvsvc_srvsvc_NetPathType_path = -1;
static gint hf_srvsvc_srvsvc_DFSFlags_FLAGS_ALLOW_NAMESPACE_CACHING = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo102_users = -1;
static gint hf_srvsvc_srvsvc_NetTransportCtr_ctr2 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_enableforcedlogoff = -1;
static gint hf_srvsvc_srvsvc_NetSessInfo2_time = -1;
static gint hf_srvsvc_srvsvc_NetPRNameCompare_name_type = -1;
static gint hf_srvsvc_srvsvc_NetPathCanonicalize_maxbuf = -1;
static gint hf_srvsvc_srvsvc_NetShareGetInfo_share_name = -1;
static gint hf_srvsvc_srvsvc_NetPRNameCompare_name1 = -1;
static gint hf_srvsvc_srvsvc_NetShareDelSticky_reserved = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr1005_array = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1524_minkeepcomplsearch = -1;
static gint hf_srvsvc_srvsvc_NetTransportDel_unknown = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_numlockthreads = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo502_enableforcedlogoff = -1;
static gint hf_srvsvc_srvsvc_NetCharDevCtr_ctr1 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_errortreshold = -1;
static gint hf_srvsvc_srvsvc_NetSessInfo1_user_flags = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo1004_comment = -1;
static gint hf_srvsvc_srvsvc_Statistics_reqbufneed = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_enablesharednetdrives = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo502_permissions = -1;
static gint hf_srvsvc_srvsvc_NetFileEnum_max_buffer = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo1_addr = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo502_type = -1;
static gint hf_srvsvc_srvsvc_NetShareCheck_server_unc = -1;
static gint hf_srvsvc_srvsvc_DFSFlags_FLAGS_RESTRICT_EXCLUSIVE_OPENS = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr0_count = -1;
static gint hf_srvsvc_srvsvc_NetServerTransportAddEx_level = -1;
static gint hf_srvsvc_srvsvc_NetCharDevControl_opcode = -1;
static gint hf_srvsvc_srvsvc_NetConnCtr1_count = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1516_timesource = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQGetInfo_info = -1;
static gint hf_srvsvc_srvsvc_DFSFlags_SHARE_1005_FLAGS_IN_DFS = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr_ctr1 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info503 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_chdevqs = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_rawworkitems = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1017 = -1;
static gint hf_srvsvc_srvsvc_NetSessInfo2_idle_time = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo102_comment = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_sesssvc = -1;
static gint hf_srvsvc_srvsvc_NetCharDevInfo1_status = -1;
static gint hf_srvsvc_srvsvc_NetSessEnum_max_buffer = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQPurge_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetFileEnum_path = -1;
static gint hf_srvsvc_srvsvc_NetServerSetServiceBitsEx_servicebits = -1;
static gint hf_srvsvc_srvsvc_NetSessCtr0_array = -1;
static gint hf_srvsvc_srvsvc_NetPathCompare_path1 = -1;
static gint hf_srvsvc_srvsvc_NetServerSetServiceBitsEx_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetFileGetInfo_info = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQCtr_ctr0 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_connections = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_sizereqbufs = -1;
static gint hf_srvsvc_srvsvc_NetFileCtr_ctr3 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_initfiletable = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1528_scavtimeout = -1;
static gint hf_srvsvc_srvsvc_NetCharDevEnum_resume_handle = -1;
static gint hf_srvsvc_srvsvc_NetPathCanonicalize_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo2_password = -1;
static gint hf_srvsvc_srvsvc_NetCharDevCtr_ctr0 = -1;
static gint hf_srvsvc_srvsvc_NetFileClose_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_lmannounce = -1;
static gint hf_srvsvc_srvsvc_NetTransportEnum_resume_handle = -1;
static gint hf_srvsvc_srvsvc_NetShareDelStart_share = -1;
static gint hf_srvsvc_srvsvc_NetSessInfo2_num_open = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo101_server_name = -1;
static gint hf_srvsvc_srvsvc_NetTransportCtr_ctr3 = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr2_count = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1518 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_netioalert = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo_info1004 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_numadmin = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_lmannounce = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_sizereqbufs = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1523 = -1;
static gint hf_srvsvc_srvsvc_NetSetFileSecurity_share = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo502_maxrawbuflen = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1548 = -1;
static gint hf_srvsvc_srvsvc_NetRemoteTOD_info = -1;
static gint hf_srvsvc_srvsvc_NetConnEnum_ctr = -1;
static gint hf_srvsvc_srvsvc_NetSessCtr1_count = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1518_lmannounce = -1;
static gint hf_srvsvc_srvsvc_NetSessInfo2_user = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo1_vcs = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQPurgeSelf_queue_name = -1;
static gint hf_srvsvc_srvsvc_NetConnInfo1_num_users = -1;
static gint hf_srvsvc_srvsvc_NetTransportDel_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_sessopen = -1;
static gint hf_srvsvc_srvsvc_NetCharDevCtr0_count = -1;
static gint hf_srvsvc_srvsvc_NetSessCtr1_array = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_initconntable = -1;
static gint hf_srvsvc_srvsvc_NetShareSetInfo_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1545 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1553 = -1;
static gint hf_srvsvc_srvsvc_NetSessEnum_resume_handle = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1514 = -1;
static gint hf_srvsvc_srvsvc_NetShareSetInfo_level = -1;
static gint hf_srvsvc_srvsvc_Statistics_fopens = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1016 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_maxworkitems = -1;
static gint hf_srvsvc_srvsvc_NetDiskInfo_count = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_glist_mtime = -1;
static gint hf_srvsvc_srvsvc_Statistics_bigbufneed = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr_ctr2 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1510_sessusers = -1;
static gint hf_srvsvc_srvsvc_NetTransportDel_transport = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo502_enablesoftcompat = -1;
static gint hf_srvsvc_srvsvc_NetPathType_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1513_maxpagedmemoryusage = -1;
static gint hf_srvsvc_srvsvc_NetServerStatisticsGet_service = -1;
static gint hf_srvsvc_srvsvc_NetTransportCtr3_array = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQInfo1_devices = -1;
static gint hf_srvsvc_srvsvc_SessionUserFlags_SESS_GUEST = -1;
static gint hf_srvsvc_srvsvc_NetSessInfo502_client_type = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_activelocks = -1;
static gint hf_srvsvc_srvsvc_NetServerStatisticsGet_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetSessCtr_ctr502 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_netioalert = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1553_minlinkthroughput = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo2_current_users = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo502_sessusers = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_irpstacksize = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQSetInfo_info = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_sizereqbufs = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1530_minfreeworkitems = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo2_max_users = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo2_domain = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo2_type = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_minrcvqueue = -1;
static gint hf_srvsvc_srvsvc_NetSessCtr0_count = -1;
static gint hf_srvsvc_srvsvc_NetCharDevControl_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo2_name = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_maxcopywritelen = -1;
static gint hf_srvsvc_srvsvc_NetCharDevGetInfo_info = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo502_sizereqbufs = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo3_password_len = -1;
static gint hf_srvsvc_srvsvc_NetCharDevInfo1_user = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_security = -1;
static gint hf_srvsvc_srvsvc_NetCharDevGetInfo_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetSessDel_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1547_alertsched = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1546 = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQGetInfo_level = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo502_unknown = -1;
static gint hf_srvsvc_srvsvc_Statistics_avresponse = -1;
static gint hf_srvsvc_srvsvc_NetShareDel_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo2_addr_len = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_alerts = -1;
static gint hf_srvsvc_srvsvc_NetCharDevControl_device_name = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo502_sessopen = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_enableraw = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1523_maxkeepsearch = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_sessopen = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1107_users = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_scavtimeout = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1520_maxcopyreadlen = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1506 = -1;
static gint hf_srvsvc_srvsvc_NetSessInfo0_client = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_initsearchtable = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_maxworkitems = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_reserved = -1;
static gint hf_srvsvc_srvsvc_NetSrvSetInfo_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetFileEnum_user = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo502_path = -1;
static gint hf_srvsvc_srvsvc_NetFileInfo3_fid = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1538 = -1;
static gint hf_srvsvc_srvsvc_Statistics_permerrors = -1;
static gint hf_srvsvc_srvsvc_NetTransportAdd_info = -1;
static gint hf_srvsvc_srvsvc_NetDiskEnum_resume_handle = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo0_vcs = -1;
static gint hf_srvsvc_srvsvc_NetFileInfo3_path = -1;
static gint hf_srvsvc_srvsvc_NetCharDevEnum_level = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo1_name = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQEnum_ctr = -1;
static gint hf_srvsvc_srvsvc_NetSessCtr10_count = -1;
static gint hf_srvsvc_sec_desc_buf_len = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr_ctr1005 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_sessconns = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_initworkitems = -1;
static gint hf_srvsvc_srvsvc_NetCharDevEnum_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo502_password = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1521_maxcopywritelen = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_minkeepsearch = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_srvheuristics = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo_info2 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_lanmask = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1541 = -1;
static gint hf_srvsvc_srvsvc_NetSessCtr_ctr2 = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo1_comment = -1;
static gint hf_srvsvc_srvsvc_NetSessCtr502_count = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1506_maxworkitems = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo502_current_users = -1;
static gint hf_srvsvc_srvsvc_NetServerStatisticsGet_stat = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQInfo_info1 = -1;
static gint hf_srvsvc_srvsvc_NetSessEnum_totalentries = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_chdevs = -1;
static gint hf_srvsvc_srvsvc_NetCharDevEnum_max_buffer = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info402 = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo2_name = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_enablesoftcompat = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo_info3 = -1;
static gint hf_srvsvc_srvsvc_NetRemoteTODInfo_month = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1501_sessopens = -1;
static gint hf_srvsvc_werror = -1;
static gint hf_srvsvc_srvsvc_NetRemoteTODInfo_day = -1;
static gint hf_srvsvc_srvsvc_NetNameValidate_flags = -1;
static gint hf_srvsvc_srvsvc_NetFileInfo3_permissions = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_sessusers = -1;
static gint hf_srvsvc_srvsvc_NetConnEnum_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_enableoplocks = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo100_platform_id = -1;
static gint hf_srvsvc_srvsvc_NetSessCtr502_array = -1;
static gint hf_srvsvc_srvsvc_NetRemoteTODInfo_msecs = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_irpstacksize = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_enableraw = -1;
static gint hf_srvsvc_srvsvc_NetServerStatisticsGet_level = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_sesssvc = -1;
static gint hf_srvsvc_srvsvc_NetServerStatisticsGet_options = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info102 = -1;
static gint hf_srvsvc_srvsvc_Statistics_bytesrcvd_high = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_numbigbufs = -1;
static gint hf_srvsvc_srvsvc_NetPathCanonicalize_can_path = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo_info1 = -1;
static gint hf_srvsvc_srvsvc_NetTransportEnum_totalentries = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr1007_array = -1;
static gint hf_srvsvc_srvsvc_NetShareEnumAll_resume_handle = -1;
static gint hf_srvsvc_srvsvc_NetPRNameCompare_flags = -1;
static gint hf_srvsvc_srvsvc_NetPathType_pathtype = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1533_maxmpxct = -1;
static gint hf_srvsvc_srvsvc_Statistics_devopens = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1556 = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQEnum_max_buffer = -1;
static gint hf_srvsvc_srvsvc_NetConnEnum_path = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_sessopen = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo102_disc = -1;
static gint hf_srvsvc_srvsvc_NetFileInfo3_num_locks = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo3_net_addr = -1;
static gint hf_srvsvc_srvsvc_NetSrvSetInfo_level = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr1006_array = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo402_sessreqs = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_autopath = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo102_server_name = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1546_initsearchtable = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr1005_count = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo2_path = -1;
static gint hf_srvsvc_srvsvc_NetSessEnum_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_chdevqs = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo2_net_addr = -1;
static gint hf_srvsvc_srvsvc_NetServerSetServiceBitsEx_transport = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_logonalert = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo403_auditprofile = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_enablefcbopens = -1;
static gint hf_srvsvc_srvsvc_NetSessEnum_user = -1;
static gint hf_srvsvc_srvsvc_NetRemoteTODInfo_timezone = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_oplockbreakresponsewait = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo1_net_addr = -1;
static gint hf_srvsvc_srvsvc_DFSFlags_CSC_CACHE_AUTO_REINT = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQGetInfo_user = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo503_maxkeepsearch = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQCtr0_count = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1503_opensearch = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo102_userpath = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1555 = -1;
static gint hf_srvsvc_srvsvc_NetSessInfo10_user = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo599_alertsched = -1;
static gint hf_srvsvc_srvsvc_NetPathCompare_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1547 = -1;
static gint hf_srvsvc_srvsvc_NetTransportInfo1_name = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo502_max_users = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo502_opensearch = -1;
static gint hf_srvsvc_srvsvc_DFSFlags_FLAGS_ACCESS_BASED_DIRECTORY_ENUM = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQInfo_info0 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo102_hidden = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr_ctr1501 = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1539 = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo501_comment = -1;
static gint hf_srvsvc_srvsvc_NetTransportEnum_transports = -1;
static gint hf_srvsvc_srvsvc_NetTransportCtr2_array = -1;
static gint hf_srvsvc_srvsvc_NetShareInfo502_name = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1535_oplockbreakresponsewait = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQInfo1_users = -1;
static gint hf_srvsvc_srvsvc_NetSessCtr_ctr1 = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQPurgeSelf_server_unc = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo1010_disc = -1;
static gint hf_srvsvc_srvsvc_NetCharDevQPurgeSelf_computer_name = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo101_server_type = -1;
static gint hf_srvsvc_srvsvc_NetShareCtr502_array = -1;
static gint hf_srvsvc_srvsvc_NetSrvInfo_info1530 = -1;

static gint proto_dcerpc_srvsvc = -1;
/* Version information */


static e_uuid_t uuid_dcerpc_srvsvc = {
	0x4b324fc8, 0x1670, 0x01d3,
	{ 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88 }
};
static guint16 ver_dcerpc_srvsvc = 3;

static int srvsvc_dissect_element_NetCharDevInfo0_device(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevInfo0_device_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevCtr0_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevCtr0_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevCtr0_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevCtr0_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevInfo1_device(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevInfo1_device_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevInfo1_status(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevInfo1_user(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevInfo1_user_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevInfo1_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevCtr1_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevCtr1_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevCtr1_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevCtr1_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevInfo_info0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevInfo_info0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevInfo_info1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevInfo_info1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevCtr_ctr0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevCtr_ctr0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevCtr_ctr1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevCtr_ctr1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQInfo0_device(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQInfo0_device_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQCtr0_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQCtr0_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQCtr0_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQCtr0_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQInfo1_device(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQInfo1_device_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQInfo1_priority(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQInfo1_devices(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQInfo1_devices_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQInfo1_users(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQInfo1_num_ahead(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQCtr1_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQCtr1_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQCtr1_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQCtr1_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQInfo_info0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQInfo_info0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQInfo_info1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQInfo_info1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQCtr_ctr0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQCtr_ctr0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQCtr_ctr1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQCtr_ctr1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnInfo0_conn_id(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnCtr0_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnCtr0_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnCtr0_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnCtr0_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnInfo1_conn_id(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnInfo1_conn_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnInfo1_num_open(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnInfo1_num_users(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnInfo1_conn_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnInfo1_user(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnInfo1_user_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnInfo1_share(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnInfo1_share_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnCtr1_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnCtr1_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnCtr1_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnCtr1_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnCtr_ctr0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnCtr_ctr0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnCtr_ctr1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnCtr_ctr1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileInfo2_fid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileCtr2_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileCtr2_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileCtr2_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileCtr2_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileInfo3_fid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileInfo3_permissions(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileInfo3_num_locks(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileInfo3_path(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileInfo3_path_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileInfo3_user(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileInfo3_user_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileCtr3_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileCtr3_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileCtr3_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileCtr3_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileInfo_info2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileInfo_info2_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileInfo_info3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileInfo_info3_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileCtr_ctr2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileCtr_ctr2_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileCtr_ctr3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileCtr_ctr3_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static const true_false_string srvsvc_SessionUserFlags_SESS_GUEST_tfs = {
   "SESS_GUEST is SET",
   "SESS_GUEST is NOT SET",
};
static const true_false_string srvsvc_SessionUserFlags_SESS_NOENCRYPTION_tfs = {
   "SESS_NOENCRYPTION is SET",
   "SESS_NOENCRYPTION is NOT SET",
};
static int srvsvc_dissect_element_NetSessInfo0_client(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo0_client_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr0_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr0_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr0_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr0_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo1_client(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo1_client_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo1_user(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo1_user_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo1_num_open(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo1_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo1_idle_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo1_user_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr1_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr1_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr1_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr1_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo2_client(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo2_client_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo2_user(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo2_user_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo2_num_open(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo2_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo2_idle_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo2_user_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo2_client_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo2_client_type_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr2_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr2_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr2_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr2_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo10_client(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo10_client_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo10_user(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo10_user_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo10_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo10_idle_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr10_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr10_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr10_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr10_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo502_client(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo502_client_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo502_user(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo502_user_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo502_num_open(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo502_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo502_idle_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo502_user_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo502_client_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo502_client_type_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo502_transport(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessInfo502_transport_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr502_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr502_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr502_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr502_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr_ctr0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr_ctr0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr_ctr1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr_ctr1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr_ctr2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr_ctr2_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr_ctr10(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr_ctr10_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr_ctr502(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessCtr_ctr502_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
const value_string srvsvc_srvsvc_ShareType_vals[] = {
	{ STYPE_DISKTREE, "STYPE_DISKTREE" },
	{ STYPE_DISKTREE_TEMPORARY, "STYPE_DISKTREE_TEMPORARY" },
	{ STYPE_DISKTREE_HIDDEN, "STYPE_DISKTREE_HIDDEN" },
	{ STYPE_PRINTQ, "STYPE_PRINTQ" },
	{ STYPE_PRINTQ_TEMPORARY, "STYPE_PRINTQ_TEMPORARY" },
	{ STYPE_PRINTQ_HIDDEN, "STYPE_PRINTQ_HIDDEN" },
	{ STYPE_DEVICE, "STYPE_DEVICE" },
	{ STYPE_DEVICE_TEMPORARY, "STYPE_DEVICE_TEMPORARY" },
	{ STYPE_DEVICE_HIDDEN, "STYPE_DEVICE_HIDDEN" },
	{ STYPE_IPC, "STYPE_IPC" },
	{ STYPE_IPC_TEMPORARY, "STYPE_IPC_TEMPORARY" },
	{ STYPE_IPC_HIDDEN, "STYPE_IPC_HIDDEN" },
{ 0, NULL }
};
static int srvsvc_dissect_element_NetShareInfo0_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo0_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo1_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo1_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo1_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo1_comment(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo1_comment_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo2_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo2_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo2_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo2_comment(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo2_comment_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo2_permissions(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo2_max_users(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo2_current_users(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo2_path(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo2_path_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo2_password(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo2_password_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo501_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo501_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo501_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo501_comment(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo501_comment_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo501_csc_policy(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo502_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo502_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo502_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo502_comment(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo502_comment_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo502_permissions(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo502_max_users(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo502_current_users(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo502_path(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo502_path_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo502_password(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo502_password_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo502_unknown(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo502_sd(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo502_sd_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo1004_comment(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo1004_comment_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo1006_max_users(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static const true_false_string srvsvc_DFSFlags_SHARE_1005_FLAGS_IN_DFS_tfs = {
   "SHARE_1005_FLAGS_IN_DFS is SET",
   "SHARE_1005_FLAGS_IN_DFS is NOT SET",
};
static const true_false_string srvsvc_DFSFlags_SHARE_1005_FLAGS_DFS_ROOT_tfs = {
   "SHARE_1005_FLAGS_DFS_ROOT is SET",
   "SHARE_1005_FLAGS_DFS_ROOT is NOT SET",
};
static const true_false_string srvsvc_DFSFlags_CSC_CACHE_AUTO_REINT_tfs = {
   "CSC_CACHE_AUTO_REINT is SET",
   "CSC_CACHE_AUTO_REINT is NOT SET",
};
static const true_false_string srvsvc_DFSFlags_CSC_CACHE_VDO_tfs = {
   "CSC_CACHE_VDO is SET",
   "CSC_CACHE_VDO is NOT SET",
};
static const true_false_string srvsvc_DFSFlags_FLAGS_RESTRICT_EXCLUSIVE_OPENS_tfs = {
   "FLAGS_RESTRICT_EXCLUSIVE_OPENS is SET",
   "FLAGS_RESTRICT_EXCLUSIVE_OPENS is NOT SET",
};
static const true_false_string srvsvc_DFSFlags_FLAGS_FORCE_SHARED_DELETE_tfs = {
   "FLAGS_FORCE_SHARED_DELETE is SET",
   "FLAGS_FORCE_SHARED_DELETE is NOT SET",
};
static const true_false_string srvsvc_DFSFlags_FLAGS_ALLOW_NAMESPACE_CACHING_tfs = {
   "FLAGS_ALLOW_NAMESPACE_CACHING is SET",
   "FLAGS_ALLOW_NAMESPACE_CACHING is NOT SET",
};
static const true_false_string srvsvc_DFSFlags_FLAGS_ACCESS_BASED_DIRECTORY_ENUM_tfs = {
   "FLAGS_ACCESS_BASED_DIRECTORY_ENUM is SET",
   "FLAGS_ACCESS_BASED_DIRECTORY_ENUM is NOT SET",
};
static int srvsvc_dissect_element_NetShareCtr0_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr0_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr0_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr0_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr1_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr1_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr1_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr1_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr2_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr2_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr2_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr2_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr501_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr501_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr501_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr501_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr502_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr502_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr502_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr502_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr1004_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr1004_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr1004_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr1004_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo1005_dfs_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr1005_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr1005_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr1005_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr1005_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr1006_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr1006_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr1006_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr1006_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo1007_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo1007_alternate_directory_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo1007_alternate_directory_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr1007_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr1007_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr1007_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr1007_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr1501_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr1501_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr1501_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr1501_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo_info0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo_info0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo_info1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo_info1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo_info2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo_info2_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo_info501(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo_info501_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo_info502(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo_info502_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo_info1004(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo_info1004_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo_info1005(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo_info1005_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo_info1006(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo_info1006_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo_info1007(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo_info1007_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo_info1501(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareInfo_info1501_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr_ctr0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr_ctr0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr_ctr1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr_ctr1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr_ctr2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr_ctr2_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr_ctr501(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr_ctr501_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr_ctr502(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr_ctr502_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr_ctr1004(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr_ctr1004_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr_ctr1005(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr_ctr1005_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr_ctr1006(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr_ctr1006_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr_ctr1007(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr_ctr1007_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr_ctr1501(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCtr_ctr1501_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
const value_string srvsvc_srvsvc_PlatformId_vals[] = {
	{ PLATFORM_ID_DOS, "PLATFORM_ID_DOS" },
	{ PLATFORM_ID_OS2, "PLATFORM_ID_OS2" },
	{ PLATFORM_ID_NT, "PLATFORM_ID_NT" },
	{ PLATFORM_ID_OSF, "PLATFORM_ID_OSF" },
	{ PLATFORM_ID_VMS, "PLATFORM_ID_VMS" },
{ 0, NULL }
};
static int srvsvc_dissect_element_NetSrvInfo100_platform_id(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo100_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo100_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo101_platform_id(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo101_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo101_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo101_version_major(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo101_version_minor(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo101_server_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo101_comment(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo101_comment_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo102_platform_id(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo102_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo102_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo102_version_major(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo102_version_minor(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo102_server_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo102_comment(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo102_comment_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo102_users(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo102_disc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo102_hidden(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo102_announce(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo102_anndelta(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo102_licenses(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo102_userpath(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo102_userpath_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_ulist_mtime(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_glist_mtime(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_alist_mtime(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_alerts(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_alerts_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_security(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_numadmin(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_lanmask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_guestaccount(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_guestaccount_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_chdevs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_chdevqs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_chdevjobs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_connections(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_shares(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_openfiles(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_sessopen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_sesssvc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_sessreqs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_opensearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_activelocks(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_sizereqbufs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_numbigbufs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_numfiletasks(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_alertsched(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_erroralert(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_logonalert(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_accessalert(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_diskalert(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_netioalert(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_maxaudits(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_srvheuristics(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo402_srvheuristics_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_ulist_mtime(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_glist_mtime(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_alist_mtime(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_alerts(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_alerts_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_security(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_numadmin(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_lanmask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_guestaccount(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_guestaccount_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_chdevs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_chdevqs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_chdevjobs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_connections(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_shares(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_openfiles(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_sessopen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_sesssvc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_sessreqs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_opensearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_activelocks(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_sizereqbufs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_numbigbufs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_numfiletasks(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_alertsched(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_eroralert(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_logonalert(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_accessalert(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_diskalert(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_netioalert(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_maxaudits(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_srvheuristics(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_srvheuristics_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_auditedevents(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_auditprofile(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_autopath(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo403_autopath_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo502_sessopen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo502_sesssvc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo502_opensearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo502_sizereqbufs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo502_initworkitems(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo502_maxworkitems(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo502_rawworkitems(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo502_irpstacksize(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo502_maxrawbuflen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo502_sessusers(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo502_sessconns(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo502_maxpagedmemoryusage(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo502_maxnonpagedmemoryusage(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo502_enablesoftcompat(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo502_enableforcedlogoff(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo502_timesource(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo502_acceptdownlevelapis(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo502_lmannounce(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_sessopen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_sesssvc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_opensearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_sizereqbufs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_initworkitems(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_maxworkitems(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_rawworkitems(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_irpstacksize(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_maxrawbuflen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_sessusers(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_sessconns(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_maxpagedmemoryusage(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_maxnonpagedmemoryusage(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_enablesoftcompat(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_enableforcedlogoff(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_timesource(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_acceptdownlevelapis(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_lmannounce(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_domain(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_domain_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_maxcopyreadlen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_maxcopywritelen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_minkeepsearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_maxkeepsearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_minkeepcomplsearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_maxkeepcomplsearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_threadcountadd(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_numlockthreads(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_scavtimeout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_minrcvqueue(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_minfreeworkitems(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_xactmemsize(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_threadpriority(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_maxmpxct(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_oplockbreakwait(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_oplockbreakresponsewait(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_enableoplocks(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_enableoplockforceclose(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_enablefcbopens(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_enableraw(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_enablesharednetdrives(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_minfreeconnections(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo503_maxfreeconnections(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_sessopen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_sesssvc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_opensearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_sizereqbufs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_initworkitems(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_maxworkitems(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_rawworkitems(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_irpstacksize(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_maxrawbuflen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_sessusers(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_sessconns(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_maxpagedmemoryusage(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_maxnonpagedmemoryusage(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_enablesoftcompat(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_enableforcedlogoff(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_timesource(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_acceptdownlevelapis(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_lmannounce(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_domain(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_domain_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_maxcopyreadlen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_maxcopywritelen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_minkeepsearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_minkeepcomplsearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_maxkeepcomplsearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_threadcountadd(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_numlockthreads(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_scavtimeout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_minrcvqueue(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_minfreeworkitems(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_xactmemsize(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_threadpriority(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_maxmpxct(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_oplockbreakwait(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_oplockbreakresponsewait(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_enableoplocks(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_enableoplockforceclose(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_enablefcbopens(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_enableraw(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_enablesharednetdrives(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_minfreeconnections(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_maxfreeconnections(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_initsesstable(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_initconntable(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_initfiletable(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_initsearchtable(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_alertsched(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_errortreshold(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_networkerrortreshold(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_diskspacetreshold(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_reserved(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_maxlinkdelay(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_minlinkthroughput(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_linkinfovalidtime(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_scavqosinfoupdatetime(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo599_maxworkitemidletime(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1005_comment(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1005_comment_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1010_disc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1016_hidden(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1017_announce(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1018_anndelta(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1107_users(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1501_sessopens(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1502_sessvcs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1503_opensearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1506_maxworkitems(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1509_maxrawbuflen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1510_sessusers(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1511_sesscons(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1512_maxnonpagedmemoryusage(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1513_maxpagedmemoryusage(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1514_enablesoftcompat(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1515_enableforcedlogoff(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1516_timesource(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1518_lmannounce(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1520_maxcopyreadlen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1521_maxcopywritelen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1522_minkeepsearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1523_maxkeepsearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1524_minkeepcomplsearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1525_maxkeepcomplsearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1528_scavtimeout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1529_minrcvqueue(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1530_minfreeworkitems(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1533_maxmpxct(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1534_oplockbreakwait(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1535_oplockbreakresponsewait(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1536_enableoplocks(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1537_enableoplockforceclose(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1538_enablefcbopens(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1539_enableraw(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1540_enablesharednetdrives(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1541_minfreeconnections(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1542_maxfreeconnections(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1543_initsesstable(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1544_initconntable(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1545_initfiletable(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1546_initsearchtable(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1547_alertsched(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1548_errortreshold(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1549_networkerrortreshold(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1550_diskspacetreshold(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1552_maxlinkdelay(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1553_minlinkthroughput(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1554_linkinfovalidtime(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1555_scavqosinfoupdatetime(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo1556_maxworkitemidletime(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info100(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info100_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info101(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info101_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info102(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info102_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info402(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info402_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info403(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info403_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info502(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info502_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info503(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info503_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info599(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info599_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1005(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1005_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1010(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1010_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1016(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1016_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1017(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1017_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1018(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1018_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1107(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1107_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1501(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1501_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1502(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1502_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1503(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1503_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1506(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1506_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1509(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1509_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1510(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1510_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1511(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1511_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1512(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1512_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1513(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1513_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1514(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1514_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1515(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1515_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1516(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1516_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1518(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1518_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1520(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1520_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1521(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1521_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1522(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1522_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1523(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1523_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1524(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1524_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1525(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1525_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1528(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1528_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1529(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1529_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1530(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1530_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1533(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1533_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1534(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1534_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1535(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1535_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1536(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1536_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1537(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1537_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1538(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1538_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1539(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1539_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1540(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1540_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1541(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1541_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1542(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1542_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1543(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1543_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1544(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1544_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1545(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1545_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1546(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1546_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1547(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1547_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1548(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1548_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1549(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1549_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1550(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1550_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1552(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1552_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1553(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1553_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1554(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1554_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1555(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1555_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1556(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvInfo_info1556_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetDiskInfo0_disk(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetDiskInfo_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetDiskInfo_disks(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetDiskInfo_disks_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetDiskInfo_disks__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_Statistics_start(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_Statistics_fopens(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_Statistics_devopens(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_Statistics_jobsqueued(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_Statistics_sopens(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_Statistics_stimeouts(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_Statistics_serrorout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_Statistics_pwerrors(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_Statistics_permerrors(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_Statistics_syserrors(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_Statistics_bytessent_low(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_Statistics_bytessent_high(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_Statistics_bytesrcvd_low(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_Statistics_bytesrcvd_high(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_Statistics_avresponse(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_Statistics_reqbufneed(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_Statistics_bigbufneed(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo0_vcs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo0_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo0_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo0_addr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo0_addr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo0_addr__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo0_addr_len(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo0_net_addr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo0_net_addr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportCtr0_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportCtr0_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportCtr0_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportCtr0_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo1_vcs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo1_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo1_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo1_addr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo1_addr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo1_addr__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo1_addr_len(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo1_net_addr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo1_net_addr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo1_domain(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo1_domain_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportCtr1_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportCtr1_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportCtr1_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportCtr1_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static const true_false_string srvsvc_TransportFlags_SVTI2_REMAP_PIPE_NAMES_tfs = {
   "SVTI2_REMAP_PIPE_NAMES is SET",
   "SVTI2_REMAP_PIPE_NAMES is NOT SET",
};
static int srvsvc_dissect_element_NetTransportInfo2_vcs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo2_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo2_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo2_addr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo2_addr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo2_addr__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo2_addr_len(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo2_net_addr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo2_net_addr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo2_domain(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo2_domain_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo2_transport_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportCtr2_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportCtr2_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportCtr2_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportCtr2_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo3_vcs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo3_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo3_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo3_addr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo3_addr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo3_addr__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo3_addr_len(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo3_net_addr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo3_net_addr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo3_domain(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo3_domain_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo3_transport_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo3_password_len(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo3_password(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo3_password_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportCtr3_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportCtr3_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportCtr3_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportCtr3_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportCtr_ctr0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportCtr_ctr0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportCtr_ctr1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportCtr_ctr1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportCtr_ctr2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportCtr_ctr2_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportCtr_ctr3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportCtr_ctr3_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetRemoteTODInfo_elapsed(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetRemoteTODInfo_msecs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetRemoteTODInfo_hours(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetRemoteTODInfo_mins(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetRemoteTODInfo_secs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetRemoteTODInfo_hunds(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetRemoteTODInfo_timezone(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetRemoteTODInfo_tinterval(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetRemoteTODInfo_day(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetRemoteTODInfo_month(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetRemoteTODInfo_year(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetRemoteTODInfo_weekday(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo_info0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo_info1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo_info2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportInfo_info3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevEnum_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevEnum_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevEnum_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevEnum_level_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevEnum_ctr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevEnum_ctr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevEnum_max_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevEnum_totalentries(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevEnum_totalentries_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevEnum_resume_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevEnum_resume_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevGetInfo_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevGetInfo_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevGetInfo_device_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevGetInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevGetInfo_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevGetInfo_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevControl_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevControl_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevControl_device_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevControl_opcode(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQEnum_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQEnum_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQEnum_user(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQEnum_user_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQEnum_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQEnum_level_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQEnum_ctr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQEnum_ctr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQEnum_max_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQEnum_totalentries(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQEnum_totalentries_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQEnum_resume_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQEnum_resume_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQGetInfo_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQGetInfo_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQGetInfo_queue_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQGetInfo_user(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQGetInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQGetInfo_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQGetInfo_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQSetInfo_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQSetInfo_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQSetInfo_queue_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQSetInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQSetInfo_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQSetInfo_parm_error(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQSetInfo_parm_error_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQPurge_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQPurge_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQPurge_queue_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQPurgeSelf_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQPurgeSelf_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQPurgeSelf_queue_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetCharDevQPurgeSelf_computer_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnEnum_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnEnum_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnEnum_path(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnEnum_path_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnEnum_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnEnum_level_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnEnum_ctr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnEnum_ctr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnEnum_max_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnEnum_totalentries(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnEnum_totalentries_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnEnum_resume_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetConnEnum_resume_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileEnum_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileEnum_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileEnum_path(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileEnum_path_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileEnum_user(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileEnum_user_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileEnum_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileEnum_level_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileEnum_ctr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileEnum_ctr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileEnum_max_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileEnum_totalentries(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileEnum_totalentries_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileEnum_resume_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileEnum_resume_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileGetInfo_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileGetInfo_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileGetInfo_fid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileGetInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileGetInfo_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileGetInfo_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileClose_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileClose_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetFileClose_fid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessEnum_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessEnum_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessEnum_client(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessEnum_client_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessEnum_user(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessEnum_user_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessEnum_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessEnum_level_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessEnum_ctr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessEnum_ctr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessEnum_max_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessEnum_totalentries(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessEnum_totalentries_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessEnum_resume_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessEnum_resume_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessDel_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessDel_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessDel_client(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessDel_client_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessDel_user(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSessDel_user_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareAdd_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareAdd_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareAdd_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareAdd_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareAdd_parm_error(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareAdd_parm_error_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareEnumAll_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareEnumAll_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareEnumAll_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareEnumAll_level_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareEnumAll_ctr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareEnumAll_ctr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareEnumAll_max_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareEnumAll_totalentries(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareEnumAll_totalentries_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareEnumAll_resume_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareEnumAll_resume_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareGetInfo_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareGetInfo_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareGetInfo_share_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareGetInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareGetInfo_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareGetInfo_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareSetInfo_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareSetInfo_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareSetInfo_share_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareSetInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareSetInfo_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareSetInfo_parm_error(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareSetInfo_parm_error_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareDel_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareDel_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareDel_share_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareDel_reserved(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareDelSticky_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareDelSticky_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareDelSticky_share_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareDelSticky_reserved(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCheck_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCheck_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCheck_device_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCheck_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareCheck_type_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvGetInfo_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvGetInfo_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvGetInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvGetInfo_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvGetInfo_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvSetInfo_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvSetInfo_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvSetInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvSetInfo_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvSetInfo_parm_error(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSrvSetInfo_parm_error_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetDiskEnum_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetDiskEnum_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetDiskEnum_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetDiskEnum_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetDiskEnum_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetDiskEnum_maxlen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetDiskEnum_totalentries(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetDiskEnum_totalentries_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetDiskEnum_resume_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetDiskEnum_resume_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetServerStatisticsGet_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetServerStatisticsGet_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetServerStatisticsGet_service(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetServerStatisticsGet_service_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetServerStatisticsGet_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetServerStatisticsGet_options(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetServerStatisticsGet_stat(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetServerStatisticsGet_stat_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportAdd_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportAdd_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportAdd_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportAdd_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportEnum_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportEnum_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportEnum_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportEnum_level_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportEnum_transports(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportEnum_transports_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportEnum_max_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportEnum_totalentries(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportEnum_totalentries_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportEnum_resume_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportEnum_resume_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportDel_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportDel_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportDel_unknown(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetTransportDel_transport(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetRemoteTOD_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetRemoteTOD_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetRemoteTOD_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetRemoteTOD_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSetServiceBits_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSetServiceBits_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSetServiceBits_transport(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSetServiceBits_transport_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSetServiceBits_servicebits(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSetServiceBits_updateimmediately(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPathType_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPathType_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPathType_path(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPathType_pathflags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPathType_pathtype(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPathType_pathtype_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPathCanonicalize_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPathCanonicalize_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPathCanonicalize_path(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPathCanonicalize_can_path(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPathCanonicalize_can_path_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPathCanonicalize_maxbuf(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPathCanonicalize_prefix(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPathCanonicalize_pathtype(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPathCanonicalize_pathtype_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPathCanonicalize_pathflags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPathCompare_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPathCompare_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPathCompare_path1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPathCompare_path2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPathCompare_pathtype(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPathCompare_pathflags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetNameValidate_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetNameValidate_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetNameValidate_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetNameValidate_name_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetNameValidate_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPRNameCompare_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPRNameCompare_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPRNameCompare_name1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPRNameCompare_name2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPRNameCompare_name_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetPRNameCompare_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareEnum_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareEnum_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareEnum_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareEnum_level_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareEnum_ctr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareEnum_ctr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareEnum_max_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareEnum_totalentries(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareEnum_totalentries_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareEnum_resume_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareEnum_resume_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareDelStart_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareDelStart_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareDelStart_share(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareDelStart_reserved(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareDelStart_hnd(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareDelStart_hnd_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareDelCommit_hnd(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetShareDelCommit_hnd_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetGetFileSecurity_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetGetFileSecurity_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetGetFileSecurity_share(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetGetFileSecurity_share_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetGetFileSecurity_file(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetGetFileSecurity_securityinformation(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetGetFileSecurity_sd_buf(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetGetFileSecurity_sd_buf_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSetFileSecurity_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSetFileSecurity_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSetFileSecurity_share(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSetFileSecurity_share_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSetFileSecurity_file(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSetFileSecurity_securityinformation(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetSetFileSecurity_sd_buf(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetServerTransportAddEx_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetServerTransportAddEx_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetServerTransportAddEx_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetServerTransportAddEx_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetServerSetServiceBitsEx_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetServerSetServiceBitsEx_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetServerSetServiceBitsEx_emulated_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetServerSetServiceBitsEx_emulated_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetServerSetServiceBitsEx_transport(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetServerSetServiceBitsEx_transport_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetServerSetServiceBitsEx_servicebitsofinterest(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetServerSetServiceBitsEx_servicebits(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int srvsvc_dissect_element_NetServerSetServiceBitsEx_updateimmediately(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
	#include "packet-smb.h"
	#include "packet-smb-browse.h"
static int
srvsvc_dissect_sec_desc_buf(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	guint32 len;
	dcerpc_info *di;
	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
		hf_srvsvc_sec_desc_buf_len, &len);
	dissect_nt_sec_desc(tvb, offset, pinfo, tree, drep, TRUE, len,
		NULL);
	offset += len;
	return offset;
}
static int
srvsvc_dissect_element_NetShareInfo_info1501_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	return srvsvc_dissect_sec_desc_buf(tvb, offset, pinfo, tree, drep);
}
static int
srvsvc_dissect_element_NetGetFileSecurity_sd_buf_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	return srvsvc_dissect_sec_desc_buf(tvb, offset, pinfo, tree, drep);
}
static int
srvsvc_dissect_element_NetSetFileSecurity_sd_buf(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	return srvsvc_dissect_sec_desc_buf(tvb, offset, pinfo, tree, drep);
}
static int
srvsvc_dissect_element_NetShareCtr1501_array__(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	return srvsvc_dissect_sec_desc_buf(tvb, offset, pinfo, tree, drep);
}
static int
srvsvc_dissect_element_NetShareInfo502_sd_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	return srvsvc_dissect_sec_desc_buf(tvb, offset, pinfo, tree, drep);
}
static int
srvsvc_dissect_ServerType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	dcerpc_info *di;
	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}
	offset=dissect_smb_server_type_flags(tvb, offset, pinfo, tree,
		drep, 0);
	return offset;
}
static int
srvsvc_dissect_element_NetSrvInfo101_server_type(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	return srvsvc_dissect_ServerType(tvb, offset, pinfo, tree, drep);
}
static int
srvsvc_dissect_element_NetSrvInfo102_server_type(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	return srvsvc_dissect_ServerType(tvb, offset, pinfo, tree, drep);
}
static int
srvsvc_dissect_secinfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep _U_)
{
	dcerpc_info *di;
	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}
	offset=dissect_security_information_mask(tvb, tree, offset);
	return offset;
}
static int
srvsvc_dissect_element_NetGetFileSecurity_securityinformation(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	 return srvsvc_dissect_secinfo(tvb, offset, pinfo, tree, drep);
}
static int
srvsvc_dissect_element_NetSetFileSecurity_securityinformation(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	 return srvsvc_dissect_secinfo(tvb, offset, pinfo, tree, drep);
}


/* IDL: struct { */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *device; */
/* IDL: } */

static int
srvsvc_dissect_element_NetCharDevInfo0_device(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevInfo0_device_, NDR_POINTER_UNIQUE, "Pointer to Device (uint16)",hf_srvsvc_srvsvc_NetCharDevInfo0_device);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevInfo0_device_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetCharDevInfo0_device, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetCharDevInfo0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetCharDevInfo0);
	}

	offset = srvsvc_dissect_element_NetCharDevInfo0_device(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] srvsvc_NetCharDevInfo0 *array; */
/* IDL: } */

static int
srvsvc_dissect_element_NetCharDevCtr0_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetCharDevCtr0_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevCtr0_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevCtr0_array_, NDR_POINTER_UNIQUE, "Pointer to Array (srvsvc_NetCharDevInfo0)",hf_srvsvc_srvsvc_NetCharDevCtr0_array);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevCtr0_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevCtr0_array__);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevCtr0_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetCharDevInfo0(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetCharDevCtr0_array,0);

	return offset;
}

int
srvsvc_dissect_struct_NetCharDevCtr0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetCharDevCtr0);
	}

	offset = srvsvc_dissect_element_NetCharDevCtr0_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetCharDevCtr0_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *device; */
/* IDL: 	uint32 status; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *user; */
/* IDL: 	uint32 time; */
/* IDL: } */

static int
srvsvc_dissect_element_NetCharDevInfo1_device(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevInfo1_device_, NDR_POINTER_UNIQUE, "Pointer to Device (uint16)",hf_srvsvc_srvsvc_NetCharDevInfo1_device);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevInfo1_device_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetCharDevInfo1_device, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevInfo1_status(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetCharDevInfo1_status, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevInfo1_user(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevInfo1_user_, NDR_POINTER_UNIQUE, "Pointer to User (uint16)",hf_srvsvc_srvsvc_NetCharDevInfo1_user);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevInfo1_user_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetCharDevInfo1_user, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevInfo1_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetCharDevInfo1_time, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetCharDevInfo1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetCharDevInfo1);
	}

	offset = srvsvc_dissect_element_NetCharDevInfo1_device(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetCharDevInfo1_status(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetCharDevInfo1_user(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetCharDevInfo1_time(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] srvsvc_NetCharDevInfo1 *array; */
/* IDL: } */

static int
srvsvc_dissect_element_NetCharDevCtr1_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetCharDevCtr1_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevCtr1_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevCtr1_array_, NDR_POINTER_UNIQUE, "Pointer to Array (srvsvc_NetCharDevInfo1)",hf_srvsvc_srvsvc_NetCharDevCtr1_array);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevCtr1_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevCtr1_array__);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevCtr1_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetCharDevInfo1(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetCharDevCtr1_array,0);

	return offset;
}

int
srvsvc_dissect_struct_NetCharDevCtr1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetCharDevCtr1);
	}

	offset = srvsvc_dissect_element_NetCharDevCtr1_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetCharDevCtr1_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: union { */
/* IDL: [case(0)] [unique(1)] [case(0)] srvsvc_NetCharDevInfo0 *info0; */
/* IDL: [case(1)] [unique(1)] [case(1)] srvsvc_NetCharDevInfo1 *info1; */
/* IDL: [default] ; */
/* IDL: } */

static int
srvsvc_dissect_element_NetCharDevInfo_info0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevInfo_info0_, NDR_POINTER_UNIQUE, "Pointer to Info0 (srvsvc_NetCharDevInfo0)",hf_srvsvc_srvsvc_NetCharDevInfo_info0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevInfo_info0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetCharDevInfo0(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetCharDevInfo_info0,0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevInfo_info1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevInfo_info1_, NDR_POINTER_UNIQUE, "Pointer to Info1 (srvsvc_NetCharDevInfo1)",hf_srvsvc_srvsvc_NetCharDevInfo_info1);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevInfo_info1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetCharDevInfo1(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetCharDevInfo_info1,0);

	return offset;
}

static int
srvsvc_dissect_NetCharDevInfo(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint32 level;

	ALIGN_TO_4_BYTES;

	old_offset = offset;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "srvsvc_NetCharDevInfo");
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetCharDevInfo);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, &level);
	switch(level) {
		case 0:
			offset = srvsvc_dissect_element_NetCharDevInfo_info0(tvb, offset, pinfo, tree, drep);
		break;

		case 1:
			offset = srvsvc_dissect_element_NetCharDevInfo_info1(tvb, offset, pinfo, tree, drep);
		break;

		default:
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: union { */
/* IDL: [case(0)] [unique(1)] [case(0)] srvsvc_NetCharDevCtr0 *ctr0; */
/* IDL: [case(1)] [unique(1)] [case(1)] srvsvc_NetCharDevCtr1 *ctr1; */
/* IDL: [default] ; */
/* IDL: } */

static int
srvsvc_dissect_element_NetCharDevCtr_ctr0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevCtr_ctr0_, NDR_POINTER_UNIQUE, "Pointer to Ctr0 (srvsvc_NetCharDevCtr0)",hf_srvsvc_srvsvc_NetCharDevCtr_ctr0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevCtr_ctr0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetCharDevCtr0(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetCharDevCtr_ctr0,0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevCtr_ctr1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevCtr_ctr1_, NDR_POINTER_UNIQUE, "Pointer to Ctr1 (srvsvc_NetCharDevCtr1)",hf_srvsvc_srvsvc_NetCharDevCtr_ctr1);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevCtr_ctr1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetCharDevCtr1(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetCharDevCtr_ctr1,0);

	return offset;
}

static int
srvsvc_dissect_NetCharDevCtr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint32 level;

	ALIGN_TO_4_BYTES;

	old_offset = offset;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "srvsvc_NetCharDevCtr");
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetCharDevCtr);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, &level);
	switch(level) {
		case 0:
			offset = srvsvc_dissect_element_NetCharDevCtr_ctr0(tvb, offset, pinfo, tree, drep);
		break;

		case 1:
			offset = srvsvc_dissect_element_NetCharDevCtr_ctr1(tvb, offset, pinfo, tree, drep);
		break;

		default:
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: struct { */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *device; */
/* IDL: } */

static int
srvsvc_dissect_element_NetCharDevQInfo0_device(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevQInfo0_device_, NDR_POINTER_UNIQUE, "Pointer to Device (uint16)",hf_srvsvc_srvsvc_NetCharDevQInfo0_device);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQInfo0_device_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetCharDevQInfo0_device, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetCharDevQInfo0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetCharDevQInfo0);
	}

	offset = srvsvc_dissect_element_NetCharDevQInfo0_device(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] srvsvc_NetCharDevQInfo0 *array; */
/* IDL: } */

static int
srvsvc_dissect_element_NetCharDevQCtr0_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetCharDevQCtr0_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQCtr0_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevQCtr0_array_, NDR_POINTER_UNIQUE, "Pointer to Array (srvsvc_NetCharDevQInfo0)",hf_srvsvc_srvsvc_NetCharDevQCtr0_array);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQCtr0_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevQCtr0_array__);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQCtr0_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetCharDevQInfo0(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetCharDevQCtr0_array,0);

	return offset;
}

int
srvsvc_dissect_struct_NetCharDevQCtr0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetCharDevQCtr0);
	}

	offset = srvsvc_dissect_element_NetCharDevQCtr0_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetCharDevQCtr0_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *device; */
/* IDL: 	uint32 priority; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *devices; */
/* IDL: 	uint32 users; */
/* IDL: 	uint32 num_ahead; */
/* IDL: } */

static int
srvsvc_dissect_element_NetCharDevQInfo1_device(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevQInfo1_device_, NDR_POINTER_UNIQUE, "Pointer to Device (uint16)",hf_srvsvc_srvsvc_NetCharDevQInfo1_device);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQInfo1_device_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetCharDevQInfo1_device, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQInfo1_priority(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetCharDevQInfo1_priority, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQInfo1_devices(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevQInfo1_devices_, NDR_POINTER_UNIQUE, "Pointer to Devices (uint16)",hf_srvsvc_srvsvc_NetCharDevQInfo1_devices);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQInfo1_devices_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetCharDevQInfo1_devices, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQInfo1_users(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetCharDevQInfo1_users, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQInfo1_num_ahead(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetCharDevQInfo1_num_ahead, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetCharDevQInfo1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetCharDevQInfo1);
	}

	offset = srvsvc_dissect_element_NetCharDevQInfo1_device(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetCharDevQInfo1_priority(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetCharDevQInfo1_devices(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetCharDevQInfo1_users(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetCharDevQInfo1_num_ahead(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] srvsvc_NetCharDevQInfo1 *array; */
/* IDL: } */

static int
srvsvc_dissect_element_NetCharDevQCtr1_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetCharDevQCtr1_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQCtr1_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevQCtr1_array_, NDR_POINTER_UNIQUE, "Pointer to Array (srvsvc_NetCharDevQInfo1)",hf_srvsvc_srvsvc_NetCharDevQCtr1_array);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQCtr1_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevQCtr1_array__);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQCtr1_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetCharDevQInfo1(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetCharDevQCtr1_array,0);

	return offset;
}

int
srvsvc_dissect_struct_NetCharDevQCtr1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetCharDevQCtr1);
	}

	offset = srvsvc_dissect_element_NetCharDevQCtr1_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetCharDevQCtr1_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: union { */
/* IDL: [case(0)] [unique(1)] [case(0)] srvsvc_NetCharDevQInfo0 *info0; */
/* IDL: [case(1)] [unique(1)] [case(1)] srvsvc_NetCharDevQInfo1 *info1; */
/* IDL: [default] ; */
/* IDL: } */

static int
srvsvc_dissect_element_NetCharDevQInfo_info0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevQInfo_info0_, NDR_POINTER_UNIQUE, "Pointer to Info0 (srvsvc_NetCharDevQInfo0)",hf_srvsvc_srvsvc_NetCharDevQInfo_info0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQInfo_info0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetCharDevQInfo0(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetCharDevQInfo_info0,0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQInfo_info1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevQInfo_info1_, NDR_POINTER_UNIQUE, "Pointer to Info1 (srvsvc_NetCharDevQInfo1)",hf_srvsvc_srvsvc_NetCharDevQInfo_info1);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQInfo_info1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetCharDevQInfo1(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetCharDevQInfo_info1,0);

	return offset;
}

static int
srvsvc_dissect_NetCharDevQInfo(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint32 level;

	ALIGN_TO_4_BYTES;

	old_offset = offset;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "srvsvc_NetCharDevQInfo");
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetCharDevQInfo);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, &level);
	switch(level) {
		case 0:
			offset = srvsvc_dissect_element_NetCharDevQInfo_info0(tvb, offset, pinfo, tree, drep);
		break;

		case 1:
			offset = srvsvc_dissect_element_NetCharDevQInfo_info1(tvb, offset, pinfo, tree, drep);
		break;

		default:
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: union { */
/* IDL: [case(0)] [unique(1)] [case(0)] srvsvc_NetCharDevQCtr0 *ctr0; */
/* IDL: [case(1)] [unique(1)] [case(1)] srvsvc_NetCharDevQCtr1 *ctr1; */
/* IDL: [default] ; */
/* IDL: } */

static int
srvsvc_dissect_element_NetCharDevQCtr_ctr0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevQCtr_ctr0_, NDR_POINTER_UNIQUE, "Pointer to Ctr0 (srvsvc_NetCharDevQCtr0)",hf_srvsvc_srvsvc_NetCharDevQCtr_ctr0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQCtr_ctr0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetCharDevQCtr0(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetCharDevQCtr_ctr0,0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQCtr_ctr1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevQCtr_ctr1_, NDR_POINTER_UNIQUE, "Pointer to Ctr1 (srvsvc_NetCharDevQCtr1)",hf_srvsvc_srvsvc_NetCharDevQCtr_ctr1);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQCtr_ctr1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetCharDevQCtr1(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetCharDevQCtr_ctr1,0);

	return offset;
}

static int
srvsvc_dissect_NetCharDevQCtr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint32 level;

	ALIGN_TO_4_BYTES;

	old_offset = offset;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "srvsvc_NetCharDevQCtr");
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetCharDevQCtr);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, &level);
	switch(level) {
		case 0:
			offset = srvsvc_dissect_element_NetCharDevQCtr_ctr0(tvb, offset, pinfo, tree, drep);
		break;

		case 1:
			offset = srvsvc_dissect_element_NetCharDevQCtr_ctr1(tvb, offset, pinfo, tree, drep);
		break;

		default:
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: struct { */
/* IDL: 	uint32 conn_id; */
/* IDL: } */

static int
srvsvc_dissect_element_NetConnInfo0_conn_id(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetConnInfo0_conn_id, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetConnInfo0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetConnInfo0);
	}

	offset = srvsvc_dissect_element_NetConnInfo0_conn_id(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] srvsvc_NetConnInfo0 *array; */
/* IDL: } */

static int
srvsvc_dissect_element_NetConnCtr0_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetConnCtr0_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetConnCtr0_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetConnCtr0_array_, NDR_POINTER_UNIQUE, "Pointer to Array (srvsvc_NetConnInfo0)",hf_srvsvc_srvsvc_NetConnCtr0_array);

	return offset;
}

static int
srvsvc_dissect_element_NetConnCtr0_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetConnCtr0_array__);

	return offset;
}

static int
srvsvc_dissect_element_NetConnCtr0_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetConnInfo0(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetConnCtr0_array,0);

	return offset;
}

int
srvsvc_dissect_struct_NetConnCtr0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetConnCtr0);
	}

	offset = srvsvc_dissect_element_NetConnCtr0_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetConnCtr0_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 conn_id; */
/* IDL: 	uint32 conn_type; */
/* IDL: 	uint32 num_open; */
/* IDL: 	uint32 num_users; */
/* IDL: 	uint32 conn_time; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *user; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *share; */
/* IDL: } */

static int
srvsvc_dissect_element_NetConnInfo1_conn_id(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetConnInfo1_conn_id, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetConnInfo1_conn_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetConnInfo1_conn_type, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetConnInfo1_num_open(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetConnInfo1_num_open, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetConnInfo1_num_users(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetConnInfo1_num_users, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetConnInfo1_conn_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetConnInfo1_conn_time, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetConnInfo1_user(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetConnInfo1_user_, NDR_POINTER_UNIQUE, "Pointer to User (uint16)",hf_srvsvc_srvsvc_NetConnInfo1_user);

	return offset;
}

static int
srvsvc_dissect_element_NetConnInfo1_user_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetConnInfo1_user, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetConnInfo1_share(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetConnInfo1_share_, NDR_POINTER_UNIQUE, "Pointer to Share (uint16)",hf_srvsvc_srvsvc_NetConnInfo1_share);

	return offset;
}

static int
srvsvc_dissect_element_NetConnInfo1_share_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetConnInfo1_share, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetConnInfo1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetConnInfo1);
	}

	offset = srvsvc_dissect_element_NetConnInfo1_conn_id(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetConnInfo1_conn_type(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetConnInfo1_num_open(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetConnInfo1_num_users(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetConnInfo1_conn_time(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetConnInfo1_user(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetConnInfo1_share(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] srvsvc_NetConnInfo1 *array; */
/* IDL: } */

static int
srvsvc_dissect_element_NetConnCtr1_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetConnCtr1_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetConnCtr1_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetConnCtr1_array_, NDR_POINTER_UNIQUE, "Pointer to Array (srvsvc_NetConnInfo1)",hf_srvsvc_srvsvc_NetConnCtr1_array);

	return offset;
}

static int
srvsvc_dissect_element_NetConnCtr1_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetConnCtr1_array__);

	return offset;
}

static int
srvsvc_dissect_element_NetConnCtr1_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetConnInfo1(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetConnCtr1_array,0);

	return offset;
}

int
srvsvc_dissect_struct_NetConnCtr1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetConnCtr1);
	}

	offset = srvsvc_dissect_element_NetConnCtr1_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetConnCtr1_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: union { */
/* IDL: [case(0)] [unique(1)] [case(0)] srvsvc_NetConnCtr0 *ctr0; */
/* IDL: [case(1)] [unique(1)] [case(1)] srvsvc_NetConnCtr1 *ctr1; */
/* IDL: [default] ; */
/* IDL: } */

static int
srvsvc_dissect_element_NetConnCtr_ctr0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetConnCtr_ctr0_, NDR_POINTER_UNIQUE, "Pointer to Ctr0 (srvsvc_NetConnCtr0)",hf_srvsvc_srvsvc_NetConnCtr_ctr0);

	return offset;
}

static int
srvsvc_dissect_element_NetConnCtr_ctr0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetConnCtr0(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetConnCtr_ctr0,0);

	return offset;
}

static int
srvsvc_dissect_element_NetConnCtr_ctr1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetConnCtr_ctr1_, NDR_POINTER_UNIQUE, "Pointer to Ctr1 (srvsvc_NetConnCtr1)",hf_srvsvc_srvsvc_NetConnCtr_ctr1);

	return offset;
}

static int
srvsvc_dissect_element_NetConnCtr_ctr1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetConnCtr1(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetConnCtr_ctr1,0);

	return offset;
}

static int
srvsvc_dissect_NetConnCtr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint32 level;

	ALIGN_TO_4_BYTES;

	old_offset = offset;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "srvsvc_NetConnCtr");
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetConnCtr);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, &level);
	switch(level) {
		case 0:
			offset = srvsvc_dissect_element_NetConnCtr_ctr0(tvb, offset, pinfo, tree, drep);
		break;

		case 1:
			offset = srvsvc_dissect_element_NetConnCtr_ctr1(tvb, offset, pinfo, tree, drep);
		break;

		default:
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: struct { */
/* IDL: 	uint32 fid; */
/* IDL: } */

static int
srvsvc_dissect_element_NetFileInfo2_fid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetFileInfo2_fid, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetFileInfo2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetFileInfo2);
	}

	offset = srvsvc_dissect_element_NetFileInfo2_fid(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] srvsvc_NetFileInfo2 *array; */
/* IDL: } */

static int
srvsvc_dissect_element_NetFileCtr2_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetFileCtr2_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetFileCtr2_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetFileCtr2_array_, NDR_POINTER_UNIQUE, "Pointer to Array (srvsvc_NetFileInfo2)",hf_srvsvc_srvsvc_NetFileCtr2_array);

	return offset;
}

static int
srvsvc_dissect_element_NetFileCtr2_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetFileCtr2_array__);

	return offset;
}

static int
srvsvc_dissect_element_NetFileCtr2_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetFileInfo2(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetFileCtr2_array,0);

	return offset;
}

int
srvsvc_dissect_struct_NetFileCtr2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetFileCtr2);
	}

	offset = srvsvc_dissect_element_NetFileCtr2_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetFileCtr2_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 fid; */
/* IDL: 	uint32 permissions; */
/* IDL: 	uint32 num_locks; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *path; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *user; */
/* IDL: } */

static int
srvsvc_dissect_element_NetFileInfo3_fid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetFileInfo3_fid, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetFileInfo3_permissions(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetFileInfo3_permissions, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetFileInfo3_num_locks(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetFileInfo3_num_locks, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetFileInfo3_path(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetFileInfo3_path_, NDR_POINTER_UNIQUE, "Pointer to Path (uint16)",hf_srvsvc_srvsvc_NetFileInfo3_path);

	return offset;
}

static int
srvsvc_dissect_element_NetFileInfo3_path_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetFileInfo3_path, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetFileInfo3_user(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetFileInfo3_user_, NDR_POINTER_UNIQUE, "Pointer to User (uint16)",hf_srvsvc_srvsvc_NetFileInfo3_user);

	return offset;
}

static int
srvsvc_dissect_element_NetFileInfo3_user_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetFileInfo3_user, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetFileInfo3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetFileInfo3);
	}

	offset = srvsvc_dissect_element_NetFileInfo3_fid(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetFileInfo3_permissions(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetFileInfo3_num_locks(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetFileInfo3_path(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetFileInfo3_user(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] srvsvc_NetFileInfo3 *array; */
/* IDL: } */

static int
srvsvc_dissect_element_NetFileCtr3_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetFileCtr3_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetFileCtr3_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetFileCtr3_array_, NDR_POINTER_UNIQUE, "Pointer to Array (srvsvc_NetFileInfo3)",hf_srvsvc_srvsvc_NetFileCtr3_array);

	return offset;
}

static int
srvsvc_dissect_element_NetFileCtr3_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetFileCtr3_array__);

	return offset;
}

static int
srvsvc_dissect_element_NetFileCtr3_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetFileInfo3(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetFileCtr3_array,0);

	return offset;
}

int
srvsvc_dissect_struct_NetFileCtr3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetFileCtr3);
	}

	offset = srvsvc_dissect_element_NetFileCtr3_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetFileCtr3_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: union { */
/* IDL: [case(2)] [unique(1)] [case(2)] srvsvc_NetFileInfo2 *info2; */
/* IDL: [case(3)] [unique(1)] [case(3)] srvsvc_NetFileInfo3 *info3; */
/* IDL: [default] ; */
/* IDL: } */

static int
srvsvc_dissect_element_NetFileInfo_info2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetFileInfo_info2_, NDR_POINTER_UNIQUE, "Pointer to Info2 (srvsvc_NetFileInfo2)",hf_srvsvc_srvsvc_NetFileInfo_info2);

	return offset;
}

static int
srvsvc_dissect_element_NetFileInfo_info2_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetFileInfo2(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetFileInfo_info2,0);

	return offset;
}

static int
srvsvc_dissect_element_NetFileInfo_info3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetFileInfo_info3_, NDR_POINTER_UNIQUE, "Pointer to Info3 (srvsvc_NetFileInfo3)",hf_srvsvc_srvsvc_NetFileInfo_info3);

	return offset;
}

static int
srvsvc_dissect_element_NetFileInfo_info3_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetFileInfo3(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetFileInfo_info3,0);

	return offset;
}

static int
srvsvc_dissect_NetFileInfo(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint32 level;

	ALIGN_TO_4_BYTES;

	old_offset = offset;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "srvsvc_NetFileInfo");
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetFileInfo);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, &level);
	switch(level) {
		case 2:
			offset = srvsvc_dissect_element_NetFileInfo_info2(tvb, offset, pinfo, tree, drep);
		break;

		case 3:
			offset = srvsvc_dissect_element_NetFileInfo_info3(tvb, offset, pinfo, tree, drep);
		break;

		default:
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: union { */
/* IDL: [case(2)] [unique(1)] [case(2)] srvsvc_NetFileCtr2 *ctr2; */
/* IDL: [case(3)] [unique(1)] [case(3)] srvsvc_NetFileCtr3 *ctr3; */
/* IDL: [default] ; */
/* IDL: } */

static int
srvsvc_dissect_element_NetFileCtr_ctr2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetFileCtr_ctr2_, NDR_POINTER_UNIQUE, "Pointer to Ctr2 (srvsvc_NetFileCtr2)",hf_srvsvc_srvsvc_NetFileCtr_ctr2);

	return offset;
}

static int
srvsvc_dissect_element_NetFileCtr_ctr2_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetFileCtr2(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetFileCtr_ctr2,0);

	return offset;
}

static int
srvsvc_dissect_element_NetFileCtr_ctr3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetFileCtr_ctr3_, NDR_POINTER_UNIQUE, "Pointer to Ctr3 (srvsvc_NetFileCtr3)",hf_srvsvc_srvsvc_NetFileCtr_ctr3);

	return offset;
}

static int
srvsvc_dissect_element_NetFileCtr_ctr3_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetFileCtr3(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetFileCtr_ctr3,0);

	return offset;
}

static int
srvsvc_dissect_NetFileCtr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint32 level;

	ALIGN_TO_4_BYTES;

	old_offset = offset;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "srvsvc_NetFileCtr");
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetFileCtr);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, &level);
	switch(level) {
		case 2:
			offset = srvsvc_dissect_element_NetFileCtr_ctr2(tvb, offset, pinfo, tree, drep);
		break;

		case 3:
			offset = srvsvc_dissect_element_NetFileCtr_ctr3(tvb, offset, pinfo, tree, drep);
		break;

		default:
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: bitmap { */
/* IDL: 	SESS_GUEST =  0x00000001 , */
/* IDL: 	SESS_NOENCRYPTION =  0x00000002 , */
/* IDL: } */

int
srvsvc_dissect_bitmap_SessionUserFlags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	guint32 flags;
	ALIGN_TO_4_BYTES;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 4, TRUE);
		tree = proto_item_add_subtree(item,ett_srvsvc_srvsvc_SessionUserFlags);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep, -1, &flags);
	proto_item_append_text(item, ": ");

	if (!flags)
		proto_item_append_text(item, "(No values set)");

	proto_tree_add_boolean(tree, hf_srvsvc_srvsvc_SessionUserFlags_SESS_GUEST, tvb, offset-4, 4, flags);
	if (flags&( 0x00000001 )){
		proto_item_append_text(item, "SESS_GUEST");
		if (flags & (~( 0x00000001 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000001 ));

	proto_tree_add_boolean(tree, hf_srvsvc_srvsvc_SessionUserFlags_SESS_NOENCRYPTION, tvb, offset-4, 4, flags);
	if (flags&( 0x00000002 )){
		proto_item_append_text(item, "SESS_NOENCRYPTION");
		if (flags & (~( 0x00000002 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000002 ));

	if (flags) {
		proto_item_append_text(item, "Unknown bitmap value 0x%x", flags);
	}

	return offset;
}


/* IDL: struct { */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *client; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSessInfo0_client(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessInfo0_client_, NDR_POINTER_UNIQUE, "Pointer to Client (uint16)",hf_srvsvc_srvsvc_NetSessInfo0_client);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo0_client_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSessInfo0_client, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSessInfo0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSessInfo0);
	}

	offset = srvsvc_dissect_element_NetSessInfo0_client(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] srvsvc_NetSessInfo0 *array; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSessCtr0_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSessCtr0_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessCtr0_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessCtr0_array_, NDR_POINTER_UNIQUE, "Pointer to Array (srvsvc_NetSessInfo0)",hf_srvsvc_srvsvc_NetSessCtr0_array);

	return offset;
}

static int
srvsvc_dissect_element_NetSessCtr0_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessCtr0_array__);

	return offset;
}

static int
srvsvc_dissect_element_NetSessCtr0_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSessInfo0(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSessCtr0_array,0);

	return offset;
}

int
srvsvc_dissect_struct_NetSessCtr0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSessCtr0);
	}

	offset = srvsvc_dissect_element_NetSessCtr0_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSessCtr0_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *client; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *user; */
/* IDL: 	uint32 num_open; */
/* IDL: 	uint32 time; */
/* IDL: 	uint32 idle_time; */
/* IDL: 	srvsvc_SessionUserFlags user_flags; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSessInfo1_client(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessInfo1_client_, NDR_POINTER_UNIQUE, "Pointer to Client (uint16)",hf_srvsvc_srvsvc_NetSessInfo1_client);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo1_client_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSessInfo1_client, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo1_user(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessInfo1_user_, NDR_POINTER_UNIQUE, "Pointer to User (uint16)",hf_srvsvc_srvsvc_NetSessInfo1_user);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo1_user_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSessInfo1_user, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo1_num_open(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSessInfo1_num_open, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo1_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSessInfo1_time, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo1_idle_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSessInfo1_idle_time, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo1_user_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_bitmap_SessionUserFlags(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSessInfo1_user_flags, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSessInfo1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSessInfo1);
	}

	offset = srvsvc_dissect_element_NetSessInfo1_client(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSessInfo1_user(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSessInfo1_num_open(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSessInfo1_time(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSessInfo1_idle_time(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSessInfo1_user_flags(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] srvsvc_NetSessInfo1 *array; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSessCtr1_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSessCtr1_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessCtr1_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessCtr1_array_, NDR_POINTER_UNIQUE, "Pointer to Array (srvsvc_NetSessInfo1)",hf_srvsvc_srvsvc_NetSessCtr1_array);

	return offset;
}

static int
srvsvc_dissect_element_NetSessCtr1_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessCtr1_array__);

	return offset;
}

static int
srvsvc_dissect_element_NetSessCtr1_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSessInfo1(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSessCtr1_array,0);

	return offset;
}

int
srvsvc_dissect_struct_NetSessCtr1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSessCtr1);
	}

	offset = srvsvc_dissect_element_NetSessCtr1_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSessCtr1_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *client; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *user; */
/* IDL: 	uint32 num_open; */
/* IDL: 	uint32 time; */
/* IDL: 	uint32 idle_time; */
/* IDL: 	srvsvc_SessionUserFlags user_flags; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *client_type; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSessInfo2_client(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessInfo2_client_, NDR_POINTER_UNIQUE, "Pointer to Client (uint16)",hf_srvsvc_srvsvc_NetSessInfo2_client);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo2_client_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSessInfo2_client, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo2_user(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessInfo2_user_, NDR_POINTER_UNIQUE, "Pointer to User (uint16)",hf_srvsvc_srvsvc_NetSessInfo2_user);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo2_user_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSessInfo2_user, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo2_num_open(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSessInfo2_num_open, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo2_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSessInfo2_time, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo2_idle_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSessInfo2_idle_time, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo2_user_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_bitmap_SessionUserFlags(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSessInfo2_user_flags, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo2_client_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessInfo2_client_type_, NDR_POINTER_UNIQUE, "Pointer to Client Type (uint16)",hf_srvsvc_srvsvc_NetSessInfo2_client_type);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo2_client_type_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSessInfo2_client_type, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSessInfo2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSessInfo2);
	}

	offset = srvsvc_dissect_element_NetSessInfo2_client(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSessInfo2_user(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSessInfo2_num_open(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSessInfo2_time(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSessInfo2_idle_time(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSessInfo2_user_flags(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSessInfo2_client_type(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] srvsvc_NetSessInfo2 *array; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSessCtr2_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSessCtr2_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessCtr2_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessCtr2_array_, NDR_POINTER_UNIQUE, "Pointer to Array (srvsvc_NetSessInfo2)",hf_srvsvc_srvsvc_NetSessCtr2_array);

	return offset;
}

static int
srvsvc_dissect_element_NetSessCtr2_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessCtr2_array__);

	return offset;
}

static int
srvsvc_dissect_element_NetSessCtr2_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSessInfo2(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSessCtr2_array,0);

	return offset;
}

int
srvsvc_dissect_struct_NetSessCtr2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSessCtr2);
	}

	offset = srvsvc_dissect_element_NetSessCtr2_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSessCtr2_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *client; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *user; */
/* IDL: 	uint32 time; */
/* IDL: 	uint32 idle_time; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSessInfo10_client(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessInfo10_client_, NDR_POINTER_UNIQUE, "Pointer to Client (uint16)",hf_srvsvc_srvsvc_NetSessInfo10_client);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo10_client_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSessInfo10_client, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo10_user(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessInfo10_user_, NDR_POINTER_UNIQUE, "Pointer to User (uint16)",hf_srvsvc_srvsvc_NetSessInfo10_user);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo10_user_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSessInfo10_user, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo10_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSessInfo10_time, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo10_idle_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSessInfo10_idle_time, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSessInfo10(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSessInfo10);
	}

	offset = srvsvc_dissect_element_NetSessInfo10_client(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSessInfo10_user(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSessInfo10_time(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSessInfo10_idle_time(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] srvsvc_NetSessInfo10 *array; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSessCtr10_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSessCtr10_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessCtr10_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessCtr10_array_, NDR_POINTER_UNIQUE, "Pointer to Array (srvsvc_NetSessInfo10)",hf_srvsvc_srvsvc_NetSessCtr10_array);

	return offset;
}

static int
srvsvc_dissect_element_NetSessCtr10_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessCtr10_array__);

	return offset;
}

static int
srvsvc_dissect_element_NetSessCtr10_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSessInfo10(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSessCtr10_array,0);

	return offset;
}

int
srvsvc_dissect_struct_NetSessCtr10(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSessCtr10);
	}

	offset = srvsvc_dissect_element_NetSessCtr10_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSessCtr10_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *client; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *user; */
/* IDL: 	uint32 num_open; */
/* IDL: 	uint32 time; */
/* IDL: 	uint32 idle_time; */
/* IDL: 	srvsvc_SessionUserFlags user_flags; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *client_type; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *transport; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSessInfo502_client(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessInfo502_client_, NDR_POINTER_UNIQUE, "Pointer to Client (uint16)",hf_srvsvc_srvsvc_NetSessInfo502_client);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo502_client_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSessInfo502_client, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo502_user(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessInfo502_user_, NDR_POINTER_UNIQUE, "Pointer to User (uint16)",hf_srvsvc_srvsvc_NetSessInfo502_user);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo502_user_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSessInfo502_user, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo502_num_open(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSessInfo502_num_open, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo502_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSessInfo502_time, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo502_idle_time(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSessInfo502_idle_time, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo502_user_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_bitmap_SessionUserFlags(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSessInfo502_user_flags, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo502_client_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessInfo502_client_type_, NDR_POINTER_UNIQUE, "Pointer to Client Type (uint16)",hf_srvsvc_srvsvc_NetSessInfo502_client_type);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo502_client_type_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSessInfo502_client_type, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo502_transport(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessInfo502_transport_, NDR_POINTER_UNIQUE, "Pointer to Transport (uint16)",hf_srvsvc_srvsvc_NetSessInfo502_transport);

	return offset;
}

static int
srvsvc_dissect_element_NetSessInfo502_transport_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSessInfo502_transport, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSessInfo502(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSessInfo502);
	}

	offset = srvsvc_dissect_element_NetSessInfo502_client(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSessInfo502_user(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSessInfo502_num_open(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSessInfo502_time(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSessInfo502_idle_time(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSessInfo502_user_flags(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSessInfo502_client_type(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSessInfo502_transport(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] srvsvc_NetSessInfo502 *array; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSessCtr502_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSessCtr502_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessCtr502_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessCtr502_array_, NDR_POINTER_UNIQUE, "Pointer to Array (srvsvc_NetSessInfo502)",hf_srvsvc_srvsvc_NetSessCtr502_array);

	return offset;
}

static int
srvsvc_dissect_element_NetSessCtr502_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessCtr502_array__);

	return offset;
}

static int
srvsvc_dissect_element_NetSessCtr502_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSessInfo502(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSessCtr502_array,0);

	return offset;
}

int
srvsvc_dissect_struct_NetSessCtr502(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSessCtr502);
	}

	offset = srvsvc_dissect_element_NetSessCtr502_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSessCtr502_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: union { */
/* IDL: [case(0)] [unique(1)] [case(0)] srvsvc_NetSessCtr0 *ctr0; */
/* IDL: [case(1)] [unique(1)] [case(1)] srvsvc_NetSessCtr1 *ctr1; */
/* IDL: [case(2)] [unique(1)] [case(2)] srvsvc_NetSessCtr2 *ctr2; */
/* IDL: [case(10)] [unique(1)] [case(10)] srvsvc_NetSessCtr10 *ctr10; */
/* IDL: [case(502)] [unique(1)] [case(502)] srvsvc_NetSessCtr502 *ctr502; */
/* IDL: [default] ; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSessCtr_ctr0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessCtr_ctr0_, NDR_POINTER_UNIQUE, "Pointer to Ctr0 (srvsvc_NetSessCtr0)",hf_srvsvc_srvsvc_NetSessCtr_ctr0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessCtr_ctr0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSessCtr0(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSessCtr_ctr0,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessCtr_ctr1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessCtr_ctr1_, NDR_POINTER_UNIQUE, "Pointer to Ctr1 (srvsvc_NetSessCtr1)",hf_srvsvc_srvsvc_NetSessCtr_ctr1);

	return offset;
}

static int
srvsvc_dissect_element_NetSessCtr_ctr1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSessCtr1(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSessCtr_ctr1,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessCtr_ctr2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessCtr_ctr2_, NDR_POINTER_UNIQUE, "Pointer to Ctr2 (srvsvc_NetSessCtr2)",hf_srvsvc_srvsvc_NetSessCtr_ctr2);

	return offset;
}

static int
srvsvc_dissect_element_NetSessCtr_ctr2_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSessCtr2(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSessCtr_ctr2,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessCtr_ctr10(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessCtr_ctr10_, NDR_POINTER_UNIQUE, "Pointer to Ctr10 (srvsvc_NetSessCtr10)",hf_srvsvc_srvsvc_NetSessCtr_ctr10);

	return offset;
}

static int
srvsvc_dissect_element_NetSessCtr_ctr10_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSessCtr10(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSessCtr_ctr10,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessCtr_ctr502(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessCtr_ctr502_, NDR_POINTER_UNIQUE, "Pointer to Ctr502 (srvsvc_NetSessCtr502)",hf_srvsvc_srvsvc_NetSessCtr_ctr502);

	return offset;
}

static int
srvsvc_dissect_element_NetSessCtr_ctr502_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSessCtr502(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSessCtr_ctr502,0);

	return offset;
}

static int
srvsvc_dissect_NetSessCtr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint32 level;

	ALIGN_TO_4_BYTES;

	old_offset = offset;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "srvsvc_NetSessCtr");
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSessCtr);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, &level);
	switch(level) {
		case 0:
			offset = srvsvc_dissect_element_NetSessCtr_ctr0(tvb, offset, pinfo, tree, drep);
		break;

		case 1:
			offset = srvsvc_dissect_element_NetSessCtr_ctr1(tvb, offset, pinfo, tree, drep);
		break;

		case 2:
			offset = srvsvc_dissect_element_NetSessCtr_ctr2(tvb, offset, pinfo, tree, drep);
		break;

		case 10:
			offset = srvsvc_dissect_element_NetSessCtr_ctr10(tvb, offset, pinfo, tree, drep);
		break;

		case 502:
			offset = srvsvc_dissect_element_NetSessCtr_ctr502(tvb, offset, pinfo, tree, drep);
		break;

		default:
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: enum { */
/* IDL: 	STYPE_DISKTREE=0, */
/* IDL: 	STYPE_DISKTREE_TEMPORARY=STYPE_DISKTREE|STYPE_TEMPORARY, */
/* IDL: 	STYPE_DISKTREE_HIDDEN=STYPE_DISKTREE|STYPE_HIDDEN, */
/* IDL: 	STYPE_PRINTQ=1, */
/* IDL: 	STYPE_PRINTQ_TEMPORARY=STYPE_PRINTQ|STYPE_TEMPORARY, */
/* IDL: 	STYPE_PRINTQ_HIDDEN=STYPE_PRINTQ|STYPE_HIDDEN, */
/* IDL: 	STYPE_DEVICE=2, */
/* IDL: 	STYPE_DEVICE_TEMPORARY=STYPE_DEVICE|STYPE_TEMPORARY, */
/* IDL: 	STYPE_DEVICE_HIDDEN=STYPE_DEVICE|STYPE_HIDDEN, */
/* IDL: 	STYPE_IPC=3, */
/* IDL: 	STYPE_IPC_TEMPORARY=STYPE_IPC|STYPE_TEMPORARY, */
/* IDL: 	STYPE_IPC_HIDDEN=STYPE_IPC|STYPE_HIDDEN, */
/* IDL: } */

int
srvsvc_dissect_enum_ShareType(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_)
{
	guint32 parameter=0;
	if(param){
		parameter=(guint32)*param;
	}
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, &parameter);
	if(param){
		*param=(guint32)parameter;
	}
	return offset;
}


/* IDL: struct { */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *name; */
/* IDL: } */

static int
srvsvc_dissect_element_NetShareInfo0_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareInfo0_name_, NDR_POINTER_UNIQUE, "Pointer to Name (uint16)",hf_srvsvc_srvsvc_NetShareInfo0_name);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo0_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareInfo0_name, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetShareInfo0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetShareInfo0);
	}

	offset = srvsvc_dissect_element_NetShareInfo0_name(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *name; */
/* IDL: 	srvsvc_ShareType type; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *comment; */
/* IDL: } */

static int
srvsvc_dissect_element_NetShareInfo1_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareInfo1_name_, NDR_POINTER_UNIQUE, "Pointer to Name (uint16)",hf_srvsvc_srvsvc_NetShareInfo1_name);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo1_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareInfo1_name, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo1_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_enum_ShareType(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareInfo1_type, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo1_comment(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareInfo1_comment_, NDR_POINTER_UNIQUE, "Pointer to Comment (uint16)",hf_srvsvc_srvsvc_NetShareInfo1_comment);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo1_comment_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareInfo1_comment, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetShareInfo1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetShareInfo1);
	}

	offset = srvsvc_dissect_element_NetShareInfo1_name(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareInfo1_type(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareInfo1_comment(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *name; */
/* IDL: 	srvsvc_ShareType type; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *comment; */
/* IDL: 	uint32 permissions; */
/* IDL: 	uint32 max_users; */
/* IDL: 	uint32 current_users; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *path; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *password; */
/* IDL: } */

static int
srvsvc_dissect_element_NetShareInfo2_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareInfo2_name_, NDR_POINTER_UNIQUE, "Pointer to Name (uint16)",hf_srvsvc_srvsvc_NetShareInfo2_name);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo2_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareInfo2_name, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo2_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_enum_ShareType(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareInfo2_type, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo2_comment(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareInfo2_comment_, NDR_POINTER_UNIQUE, "Pointer to Comment (uint16)",hf_srvsvc_srvsvc_NetShareInfo2_comment);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo2_comment_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareInfo2_comment, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo2_permissions(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareInfo2_permissions, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo2_max_users(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareInfo2_max_users, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo2_current_users(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareInfo2_current_users, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo2_path(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareInfo2_path_, NDR_POINTER_UNIQUE, "Pointer to Path (uint16)",hf_srvsvc_srvsvc_NetShareInfo2_path);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo2_path_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareInfo2_path, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo2_password(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareInfo2_password_, NDR_POINTER_UNIQUE, "Pointer to Password (uint16)",hf_srvsvc_srvsvc_NetShareInfo2_password);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo2_password_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareInfo2_password, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetShareInfo2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetShareInfo2);
	}

	offset = srvsvc_dissect_element_NetShareInfo2_name(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareInfo2_type(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareInfo2_comment(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareInfo2_permissions(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareInfo2_max_users(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareInfo2_current_users(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareInfo2_path(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareInfo2_password(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *name; */
/* IDL: 	srvsvc_ShareType type; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *comment; */
/* IDL: 	uint32 csc_policy; */
/* IDL: } */

static int
srvsvc_dissect_element_NetShareInfo501_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareInfo501_name_, NDR_POINTER_UNIQUE, "Pointer to Name (uint16)",hf_srvsvc_srvsvc_NetShareInfo501_name);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo501_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareInfo501_name, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo501_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_enum_ShareType(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareInfo501_type, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo501_comment(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareInfo501_comment_, NDR_POINTER_UNIQUE, "Pointer to Comment (uint16)",hf_srvsvc_srvsvc_NetShareInfo501_comment);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo501_comment_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareInfo501_comment, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo501_csc_policy(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareInfo501_csc_policy, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetShareInfo501(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetShareInfo501);
	}

	offset = srvsvc_dissect_element_NetShareInfo501_name(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareInfo501_type(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareInfo501_comment(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareInfo501_csc_policy(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *name; */
/* IDL: 	srvsvc_ShareType type; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *comment; */
/* IDL: 	uint32 permissions; */
/* IDL: 	int32 max_users; */
/* IDL: 	uint32 current_users; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *path; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *password; */
/* IDL: 	uint32 unknown; */
/* IDL: 	[unique(1)] [subcontext(4)] security_descriptor *sd; */
/* IDL: } */

static int
srvsvc_dissect_element_NetShareInfo502_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareInfo502_name_, NDR_POINTER_UNIQUE, "Pointer to Name (uint16)",hf_srvsvc_srvsvc_NetShareInfo502_name);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo502_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareInfo502_name, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo502_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_enum_ShareType(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareInfo502_type, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo502_comment(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareInfo502_comment_, NDR_POINTER_UNIQUE, "Pointer to Comment (uint16)",hf_srvsvc_srvsvc_NetShareInfo502_comment);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo502_comment_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareInfo502_comment, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo502_permissions(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareInfo502_permissions, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo502_max_users(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareInfo502_max_users, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo502_current_users(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareInfo502_current_users, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo502_path(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareInfo502_path_, NDR_POINTER_UNIQUE, "Pointer to Path (uint16)",hf_srvsvc_srvsvc_NetShareInfo502_path);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo502_path_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareInfo502_path, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo502_password(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareInfo502_password_, NDR_POINTER_UNIQUE, "Pointer to Password (uint16)",hf_srvsvc_srvsvc_NetShareInfo502_password);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo502_password_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareInfo502_password, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo502_unknown(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareInfo502_unknown, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo502_sd(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareInfo502_sd_, NDR_POINTER_UNIQUE, "Pointer to Sd (security_descriptor)",hf_srvsvc_srvsvc_NetShareInfo502_sd);

	return offset;
}

int
srvsvc_dissect_struct_NetShareInfo502(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetShareInfo502);
	}

	offset = srvsvc_dissect_element_NetShareInfo502_name(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareInfo502_type(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareInfo502_comment(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareInfo502_permissions(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareInfo502_max_users(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareInfo502_current_users(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareInfo502_path(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareInfo502_password(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareInfo502_unknown(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareInfo502_sd(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *comment; */
/* IDL: } */

static int
srvsvc_dissect_element_NetShareInfo1004_comment(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareInfo1004_comment_, NDR_POINTER_UNIQUE, "Pointer to Comment (uint16)",hf_srvsvc_srvsvc_NetShareInfo1004_comment);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo1004_comment_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareInfo1004_comment, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetShareInfo1004(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetShareInfo1004);
	}

	offset = srvsvc_dissect_element_NetShareInfo1004_comment(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	int32 max_users; */
/* IDL: } */

static int
srvsvc_dissect_element_NetShareInfo1006_max_users(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareInfo1006_max_users, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetShareInfo1006(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetShareInfo1006);
	}

	offset = srvsvc_dissect_element_NetShareInfo1006_max_users(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: bitmap { */
/* IDL: 	SHARE_1005_FLAGS_IN_DFS =  0x00000001 , */
/* IDL: 	SHARE_1005_FLAGS_DFS_ROOT =  0x00000002 , */
/* IDL: 	CSC_CACHE_AUTO_REINT =  0x00000010 , */
/* IDL: 	CSC_CACHE_VDO =  0x00000020 , */
/* IDL: 	FLAGS_RESTRICT_EXCLUSIVE_OPENS =  0x00000100 , */
/* IDL: 	FLAGS_FORCE_SHARED_DELETE =  0x00000200 , */
/* IDL: 	FLAGS_ALLOW_NAMESPACE_CACHING =  0x00000400 , */
/* IDL: 	FLAGS_ACCESS_BASED_DIRECTORY_ENUM =  0x00000800 , */
/* IDL: } */

int
srvsvc_dissect_bitmap_DFSFlags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	guint32 flags;
	ALIGN_TO_4_BYTES;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 4, TRUE);
		tree = proto_item_add_subtree(item,ett_srvsvc_srvsvc_DFSFlags);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep, -1, &flags);
	proto_item_append_text(item, ": ");

	if (!flags)
		proto_item_append_text(item, "(No values set)");

	proto_tree_add_boolean(tree, hf_srvsvc_srvsvc_DFSFlags_SHARE_1005_FLAGS_IN_DFS, tvb, offset-4, 4, flags);
	if (flags&( 0x00000001 )){
		proto_item_append_text(item, "SHARE_1005_FLAGS_IN_DFS");
		if (flags & (~( 0x00000001 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000001 ));

	proto_tree_add_boolean(tree, hf_srvsvc_srvsvc_DFSFlags_SHARE_1005_FLAGS_DFS_ROOT, tvb, offset-4, 4, flags);
	if (flags&( 0x00000002 )){
		proto_item_append_text(item, "SHARE_1005_FLAGS_DFS_ROOT");
		if (flags & (~( 0x00000002 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000002 ));

	proto_tree_add_boolean(tree, hf_srvsvc_srvsvc_DFSFlags_CSC_CACHE_AUTO_REINT, tvb, offset-4, 4, flags);
	if (flags&( 0x00000010 )){
		proto_item_append_text(item, "CSC_CACHE_AUTO_REINT");
		if (flags & (~( 0x00000010 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000010 ));

	proto_tree_add_boolean(tree, hf_srvsvc_srvsvc_DFSFlags_CSC_CACHE_VDO, tvb, offset-4, 4, flags);
	if (flags&( 0x00000020 )){
		proto_item_append_text(item, "CSC_CACHE_VDO");
		if (flags & (~( 0x00000020 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000020 ));

	proto_tree_add_boolean(tree, hf_srvsvc_srvsvc_DFSFlags_FLAGS_RESTRICT_EXCLUSIVE_OPENS, tvb, offset-4, 4, flags);
	if (flags&( 0x00000100 )){
		proto_item_append_text(item, "FLAGS_RESTRICT_EXCLUSIVE_OPENS");
		if (flags & (~( 0x00000100 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000100 ));

	proto_tree_add_boolean(tree, hf_srvsvc_srvsvc_DFSFlags_FLAGS_FORCE_SHARED_DELETE, tvb, offset-4, 4, flags);
	if (flags&( 0x00000200 )){
		proto_item_append_text(item, "FLAGS_FORCE_SHARED_DELETE");
		if (flags & (~( 0x00000200 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000200 ));

	proto_tree_add_boolean(tree, hf_srvsvc_srvsvc_DFSFlags_FLAGS_ALLOW_NAMESPACE_CACHING, tvb, offset-4, 4, flags);
	if (flags&( 0x00000400 )){
		proto_item_append_text(item, "FLAGS_ALLOW_NAMESPACE_CACHING");
		if (flags & (~( 0x00000400 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000400 ));

	proto_tree_add_boolean(tree, hf_srvsvc_srvsvc_DFSFlags_FLAGS_ACCESS_BASED_DIRECTORY_ENUM, tvb, offset-4, 4, flags);
	if (flags&( 0x00000800 )){
		proto_item_append_text(item, "FLAGS_ACCESS_BASED_DIRECTORY_ENUM");
		if (flags & (~( 0x00000800 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000800 ));

	if (flags) {
		proto_item_append_text(item, "Unknown bitmap value 0x%x", flags);
	}

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] srvsvc_NetShareInfo0 *array; */
/* IDL: } */

static int
srvsvc_dissect_element_NetShareCtr0_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareCtr0_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr0_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr0_array_, NDR_POINTER_UNIQUE, "Pointer to Array (srvsvc_NetShareInfo0)",hf_srvsvc_srvsvc_NetShareCtr0_array);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr0_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr0_array__);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr0_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareInfo0(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareCtr0_array,0);

	return offset;
}

int
srvsvc_dissect_struct_NetShareCtr0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetShareCtr0);
	}

	offset = srvsvc_dissect_element_NetShareCtr0_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareCtr0_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] srvsvc_NetShareInfo1 *array; */
/* IDL: } */

static int
srvsvc_dissect_element_NetShareCtr1_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareCtr1_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr1_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr1_array_, NDR_POINTER_UNIQUE, "Pointer to Array (srvsvc_NetShareInfo1)",hf_srvsvc_srvsvc_NetShareCtr1_array);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr1_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr1_array__);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr1_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareInfo1(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareCtr1_array,0);

	return offset;
}

int
srvsvc_dissect_struct_NetShareCtr1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetShareCtr1);
	}

	offset = srvsvc_dissect_element_NetShareCtr1_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareCtr1_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] srvsvc_NetShareInfo2 *array; */
/* IDL: } */

static int
srvsvc_dissect_element_NetShareCtr2_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareCtr2_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr2_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr2_array_, NDR_POINTER_UNIQUE, "Pointer to Array (srvsvc_NetShareInfo2)",hf_srvsvc_srvsvc_NetShareCtr2_array);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr2_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr2_array__);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr2_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareInfo2(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareCtr2_array,0);

	return offset;
}

int
srvsvc_dissect_struct_NetShareCtr2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetShareCtr2);
	}

	offset = srvsvc_dissect_element_NetShareCtr2_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareCtr2_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] srvsvc_NetShareInfo501 *array; */
/* IDL: } */

static int
srvsvc_dissect_element_NetShareCtr501_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareCtr501_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr501_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr501_array_, NDR_POINTER_UNIQUE, "Pointer to Array (srvsvc_NetShareInfo501)",hf_srvsvc_srvsvc_NetShareCtr501_array);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr501_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr501_array__);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr501_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareInfo501(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareCtr501_array,0);

	return offset;
}

int
srvsvc_dissect_struct_NetShareCtr501(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetShareCtr501);
	}

	offset = srvsvc_dissect_element_NetShareCtr501_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareCtr501_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] srvsvc_NetShareInfo502 *array; */
/* IDL: } */

static int
srvsvc_dissect_element_NetShareCtr502_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareCtr502_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr502_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr502_array_, NDR_POINTER_UNIQUE, "Pointer to Array (srvsvc_NetShareInfo502)",hf_srvsvc_srvsvc_NetShareCtr502_array);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr502_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr502_array__);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr502_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareInfo502(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareCtr502_array,0);

	return offset;
}

int
srvsvc_dissect_struct_NetShareCtr502(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetShareCtr502);
	}

	offset = srvsvc_dissect_element_NetShareCtr502_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareCtr502_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] srvsvc_NetShareInfo1004 *array; */
/* IDL: } */

static int
srvsvc_dissect_element_NetShareCtr1004_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareCtr1004_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr1004_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr1004_array_, NDR_POINTER_UNIQUE, "Pointer to Array (srvsvc_NetShareInfo1004)",hf_srvsvc_srvsvc_NetShareCtr1004_array);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr1004_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr1004_array__);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr1004_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareInfo1004(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareCtr1004_array,0);

	return offset;
}

int
srvsvc_dissect_struct_NetShareCtr1004(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetShareCtr1004);
	}

	offset = srvsvc_dissect_element_NetShareCtr1004_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareCtr1004_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	srvsvc_DFSFlags dfs_flags; */
/* IDL: } */

static int
srvsvc_dissect_element_NetShareInfo1005_dfs_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_bitmap_DFSFlags(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareInfo1005_dfs_flags, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetShareInfo1005(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetShareInfo1005);
	}

	offset = srvsvc_dissect_element_NetShareInfo1005_dfs_flags(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] srvsvc_NetShareInfo1005 *array; */
/* IDL: } */

static int
srvsvc_dissect_element_NetShareCtr1005_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareCtr1005_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr1005_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr1005_array_, NDR_POINTER_UNIQUE, "Pointer to Array (srvsvc_NetShareInfo1005)",hf_srvsvc_srvsvc_NetShareCtr1005_array);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr1005_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr1005_array__);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr1005_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareInfo1005(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareCtr1005_array,0);

	return offset;
}

int
srvsvc_dissect_struct_NetShareCtr1005(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetShareCtr1005);
	}

	offset = srvsvc_dissect_element_NetShareCtr1005_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareCtr1005_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] srvsvc_NetShareInfo1006 *array; */
/* IDL: } */

static int
srvsvc_dissect_element_NetShareCtr1006_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareCtr1006_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr1006_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr1006_array_, NDR_POINTER_UNIQUE, "Pointer to Array (srvsvc_NetShareInfo1006)",hf_srvsvc_srvsvc_NetShareCtr1006_array);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr1006_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr1006_array__);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr1006_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareInfo1006(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareCtr1006_array,0);

	return offset;
}

int
srvsvc_dissect_struct_NetShareCtr1006(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetShareCtr1006);
	}

	offset = srvsvc_dissect_element_NetShareCtr1006_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareCtr1006_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 flags; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *alternate_directory_name; */
/* IDL: } */

static int
srvsvc_dissect_element_NetShareInfo1007_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareInfo1007_flags, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo1007_alternate_directory_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareInfo1007_alternate_directory_name_, NDR_POINTER_UNIQUE, "Pointer to Alternate Directory Name (uint16)",hf_srvsvc_srvsvc_NetShareInfo1007_alternate_directory_name);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo1007_alternate_directory_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareInfo1007_alternate_directory_name, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetShareInfo1007(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetShareInfo1007);
	}

	offset = srvsvc_dissect_element_NetShareInfo1007_flags(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareInfo1007_alternate_directory_name(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] srvsvc_NetShareInfo1007 *array; */
/* IDL: } */

static int
srvsvc_dissect_element_NetShareCtr1007_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareCtr1007_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr1007_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr1007_array_, NDR_POINTER_UNIQUE, "Pointer to Array (srvsvc_NetShareInfo1007)",hf_srvsvc_srvsvc_NetShareCtr1007_array);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr1007_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr1007_array__);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr1007_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareInfo1007(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareCtr1007_array,0);

	return offset;
}

int
srvsvc_dissect_struct_NetShareCtr1007(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetShareCtr1007);
	}

	offset = srvsvc_dissect_element_NetShareCtr1007_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareCtr1007_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] sec_desc_buf *array; */
/* IDL: } */

static int
srvsvc_dissect_element_NetShareCtr1501_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareCtr1501_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr1501_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr1501_array_, NDR_POINTER_UNIQUE, "Pointer to Array (sec_desc_buf)",hf_srvsvc_srvsvc_NetShareCtr1501_array);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr1501_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr1501_array__);

	return offset;
}

int
srvsvc_dissect_struct_NetShareCtr1501(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetShareCtr1501);
	}

	offset = srvsvc_dissect_element_NetShareCtr1501_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetShareCtr1501_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: union { */
/* IDL: [case(0)] [unique(1)] [case(0)] srvsvc_NetShareInfo0 *info0; */
/* IDL: [case(1)] [unique(1)] [case(1)] srvsvc_NetShareInfo1 *info1; */
/* IDL: [case(2)] [unique(1)] [case(2)] srvsvc_NetShareInfo2 *info2; */
/* IDL: [case(501)] [unique(1)] [case(501)] srvsvc_NetShareInfo501 *info501; */
/* IDL: [case(502)] [unique(1)] [case(502)] srvsvc_NetShareInfo502 *info502; */
/* IDL: [case(1004)] [unique(1)] [case(1004)] srvsvc_NetShareInfo1004 *info1004; */
/* IDL: [case(1005)] [unique(1)] [case(1005)] srvsvc_NetShareInfo1005 *info1005; */
/* IDL: [case(1006)] [unique(1)] [case(1006)] srvsvc_NetShareInfo1006 *info1006; */
/* IDL: [case(1007)] [unique(1)] [case(1007)] srvsvc_NetShareInfo1007 *info1007; */
/* IDL: [case(1501)] [unique(1)] [case(1501)] sec_desc_buf *info1501; */
/* IDL: [default] ; */
/* IDL: } */

static int
srvsvc_dissect_element_NetShareInfo_info0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareInfo_info0_, NDR_POINTER_UNIQUE, "Pointer to Info0 (srvsvc_NetShareInfo0)",hf_srvsvc_srvsvc_NetShareInfo_info0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo_info0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareInfo0(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareInfo_info0,0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo_info1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareInfo_info1_, NDR_POINTER_UNIQUE, "Pointer to Info1 (srvsvc_NetShareInfo1)",hf_srvsvc_srvsvc_NetShareInfo_info1);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo_info1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareInfo1(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareInfo_info1,0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo_info2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareInfo_info2_, NDR_POINTER_UNIQUE, "Pointer to Info2 (srvsvc_NetShareInfo2)",hf_srvsvc_srvsvc_NetShareInfo_info2);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo_info2_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareInfo2(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareInfo_info2,0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo_info501(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareInfo_info501_, NDR_POINTER_UNIQUE, "Pointer to Info501 (srvsvc_NetShareInfo501)",hf_srvsvc_srvsvc_NetShareInfo_info501);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo_info501_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareInfo501(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareInfo_info501,0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo_info502(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareInfo_info502_, NDR_POINTER_UNIQUE, "Pointer to Info502 (srvsvc_NetShareInfo502)",hf_srvsvc_srvsvc_NetShareInfo_info502);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo_info502_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareInfo502(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareInfo_info502,0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo_info1004(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareInfo_info1004_, NDR_POINTER_UNIQUE, "Pointer to Info1004 (srvsvc_NetShareInfo1004)",hf_srvsvc_srvsvc_NetShareInfo_info1004);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo_info1004_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareInfo1004(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareInfo_info1004,0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo_info1005(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareInfo_info1005_, NDR_POINTER_UNIQUE, "Pointer to Info1005 (srvsvc_NetShareInfo1005)",hf_srvsvc_srvsvc_NetShareInfo_info1005);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo_info1005_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareInfo1005(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareInfo_info1005,0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo_info1006(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareInfo_info1006_, NDR_POINTER_UNIQUE, "Pointer to Info1006 (srvsvc_NetShareInfo1006)",hf_srvsvc_srvsvc_NetShareInfo_info1006);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo_info1006_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareInfo1006(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareInfo_info1006,0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo_info1007(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareInfo_info1007_, NDR_POINTER_UNIQUE, "Pointer to Info1007 (srvsvc_NetShareInfo1007)",hf_srvsvc_srvsvc_NetShareInfo_info1007);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo_info1007_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareInfo1007(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareInfo_info1007,0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareInfo_info1501(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareInfo_info1501_, NDR_POINTER_UNIQUE, "Pointer to Info1501 (sec_desc_buf)",hf_srvsvc_srvsvc_NetShareInfo_info1501);

	return offset;
}

static int
srvsvc_dissect_NetShareInfo(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint32 level;

	ALIGN_TO_4_BYTES;

	old_offset = offset;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "srvsvc_NetShareInfo");
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetShareInfo);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, &level);
	switch(level) {
		case 0:
			offset = srvsvc_dissect_element_NetShareInfo_info0(tvb, offset, pinfo, tree, drep);
		break;

		case 1:
			offset = srvsvc_dissect_element_NetShareInfo_info1(tvb, offset, pinfo, tree, drep);
		break;

		case 2:
			offset = srvsvc_dissect_element_NetShareInfo_info2(tvb, offset, pinfo, tree, drep);
		break;

		case 501:
			offset = srvsvc_dissect_element_NetShareInfo_info501(tvb, offset, pinfo, tree, drep);
		break;

		case 502:
			offset = srvsvc_dissect_element_NetShareInfo_info502(tvb, offset, pinfo, tree, drep);
		break;

		case 1004:
			offset = srvsvc_dissect_element_NetShareInfo_info1004(tvb, offset, pinfo, tree, drep);
		break;

		case 1005:
			offset = srvsvc_dissect_element_NetShareInfo_info1005(tvb, offset, pinfo, tree, drep);
		break;

		case 1006:
			offset = srvsvc_dissect_element_NetShareInfo_info1006(tvb, offset, pinfo, tree, drep);
		break;

		case 1007:
			offset = srvsvc_dissect_element_NetShareInfo_info1007(tvb, offset, pinfo, tree, drep);
		break;

		case 1501:
			offset = srvsvc_dissect_element_NetShareInfo_info1501(tvb, offset, pinfo, tree, drep);
		break;

		default:
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: union { */
/* IDL: [case(0)] [unique(1)] [case(0)] srvsvc_NetShareCtr0 *ctr0; */
/* IDL: [case(1)] [unique(1)] [case(1)] srvsvc_NetShareCtr1 *ctr1; */
/* IDL: [case(2)] [unique(1)] [case(2)] srvsvc_NetShareCtr2 *ctr2; */
/* IDL: [case(501)] [unique(1)] [case(501)] srvsvc_NetShareCtr501 *ctr501; */
/* IDL: [case(502)] [unique(1)] [case(502)] srvsvc_NetShareCtr502 *ctr502; */
/* IDL: [case(1004)] [unique(1)] [case(1004)] srvsvc_NetShareCtr1004 *ctr1004; */
/* IDL: [case(1005)] [unique(1)] [case(1005)] srvsvc_NetShareCtr1005 *ctr1005; */
/* IDL: [case(1006)] [unique(1)] [case(1006)] srvsvc_NetShareCtr1006 *ctr1006; */
/* IDL: [case(1007)] [unique(1)] [case(1007)] srvsvc_NetShareCtr1007 *ctr1007; */
/* IDL: [case(1501)] [unique(1)] [case(1501)] srvsvc_NetShareCtr1501 *ctr1501; */
/* IDL: [default] ; */
/* IDL: } */

static int
srvsvc_dissect_element_NetShareCtr_ctr0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr_ctr0_, NDR_POINTER_UNIQUE, "Pointer to Ctr0 (srvsvc_NetShareCtr0)",hf_srvsvc_srvsvc_NetShareCtr_ctr0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr_ctr0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareCtr0(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareCtr_ctr0,0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr_ctr1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr_ctr1_, NDR_POINTER_UNIQUE, "Pointer to Ctr1 (srvsvc_NetShareCtr1)",hf_srvsvc_srvsvc_NetShareCtr_ctr1);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr_ctr1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareCtr1(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareCtr_ctr1,0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr_ctr2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr_ctr2_, NDR_POINTER_UNIQUE, "Pointer to Ctr2 (srvsvc_NetShareCtr2)",hf_srvsvc_srvsvc_NetShareCtr_ctr2);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr_ctr2_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareCtr2(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareCtr_ctr2,0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr_ctr501(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr_ctr501_, NDR_POINTER_UNIQUE, "Pointer to Ctr501 (srvsvc_NetShareCtr501)",hf_srvsvc_srvsvc_NetShareCtr_ctr501);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr_ctr501_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareCtr501(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareCtr_ctr501,0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr_ctr502(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr_ctr502_, NDR_POINTER_UNIQUE, "Pointer to Ctr502 (srvsvc_NetShareCtr502)",hf_srvsvc_srvsvc_NetShareCtr_ctr502);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr_ctr502_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareCtr502(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareCtr_ctr502,0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr_ctr1004(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr_ctr1004_, NDR_POINTER_UNIQUE, "Pointer to Ctr1004 (srvsvc_NetShareCtr1004)",hf_srvsvc_srvsvc_NetShareCtr_ctr1004);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr_ctr1004_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareCtr1004(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareCtr_ctr1004,0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr_ctr1005(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr_ctr1005_, NDR_POINTER_UNIQUE, "Pointer to Ctr1005 (srvsvc_NetShareCtr1005)",hf_srvsvc_srvsvc_NetShareCtr_ctr1005);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr_ctr1005_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareCtr1005(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareCtr_ctr1005,0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr_ctr1006(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr_ctr1006_, NDR_POINTER_UNIQUE, "Pointer to Ctr1006 (srvsvc_NetShareCtr1006)",hf_srvsvc_srvsvc_NetShareCtr_ctr1006);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr_ctr1006_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareCtr1006(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareCtr_ctr1006,0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr_ctr1007(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr_ctr1007_, NDR_POINTER_UNIQUE, "Pointer to Ctr1007 (srvsvc_NetShareCtr1007)",hf_srvsvc_srvsvc_NetShareCtr_ctr1007);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr_ctr1007_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareCtr1007(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareCtr_ctr1007,0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr_ctr1501(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCtr_ctr1501_, NDR_POINTER_UNIQUE, "Pointer to Ctr1501 (srvsvc_NetShareCtr1501)",hf_srvsvc_srvsvc_NetShareCtr_ctr1501);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCtr_ctr1501_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetShareCtr1501(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetShareCtr_ctr1501,0);

	return offset;
}

static int
srvsvc_dissect_NetShareCtr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint32 level = (guint32) -1;

	ALIGN_TO_4_BYTES;

	old_offset = offset;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "srvsvc_NetShareCtr");
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetShareCtr);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, &level);
	switch(level) {
		case 0:
			offset = srvsvc_dissect_element_NetShareCtr_ctr0(tvb, offset, pinfo, tree, drep);
		break;

		case 1:
			offset = srvsvc_dissect_element_NetShareCtr_ctr1(tvb, offset, pinfo, tree, drep);
		break;

		case 2:
			offset = srvsvc_dissect_element_NetShareCtr_ctr2(tvb, offset, pinfo, tree, drep);
		break;

		case 501:
			offset = srvsvc_dissect_element_NetShareCtr_ctr501(tvb, offset, pinfo, tree, drep);
		break;

		case 502:
			offset = srvsvc_dissect_element_NetShareCtr_ctr502(tvb, offset, pinfo, tree, drep);
		break;

		case 1004:
			offset = srvsvc_dissect_element_NetShareCtr_ctr1004(tvb, offset, pinfo, tree, drep);
		break;

		case 1005:
			offset = srvsvc_dissect_element_NetShareCtr_ctr1005(tvb, offset, pinfo, tree, drep);
		break;

		case 1006:
			offset = srvsvc_dissect_element_NetShareCtr_ctr1006(tvb, offset, pinfo, tree, drep);
		break;

		case 1007:
			offset = srvsvc_dissect_element_NetShareCtr_ctr1007(tvb, offset, pinfo, tree, drep);
		break;

		case 1501:
			offset = srvsvc_dissect_element_NetShareCtr_ctr1501(tvb, offset, pinfo, tree, drep);
		break;

		default:
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: enum { */
/* IDL: 	PLATFORM_ID_DOS=300, */
/* IDL: 	PLATFORM_ID_OS2=400, */
/* IDL: 	PLATFORM_ID_NT=500, */
/* IDL: 	PLATFORM_ID_OSF=600, */
/* IDL: 	PLATFORM_ID_VMS=700, */
/* IDL: } */

int
srvsvc_dissect_enum_PlatformId(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_)
{
	guint32 parameter=0;
	if(param){
		parameter=(guint32)*param;
	}
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, &parameter);
	if(param){
		*param=(guint32)parameter;
	}
	return offset;
}


/* IDL: struct { */
/* IDL: 	srvsvc_PlatformId platform_id; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *server_name; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo100_platform_id(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_enum_PlatformId(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo100_platform_id, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo100_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo100_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_srvsvc_srvsvc_NetSrvInfo100_server_name);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo100_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSrvInfo100_server_name, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo100(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo100);
	}

	offset = srvsvc_dissect_element_NetSrvInfo100_platform_id(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo100_server_name(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	srvsvc_PlatformId platform_id; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *server_name; */
/* IDL: 	uint32 version_major; */
/* IDL: 	uint32 version_minor; */
/* IDL: 	svcctl_ServerType server_type; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *comment; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo101_platform_id(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_enum_PlatformId(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo101_platform_id, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo101_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo101_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_srvsvc_srvsvc_NetSrvInfo101_server_name);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo101_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSrvInfo101_server_name, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo101_version_major(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo101_version_major, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo101_version_minor(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo101_version_minor, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo101_comment(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo101_comment_, NDR_POINTER_UNIQUE, "Pointer to Comment (uint16)",hf_srvsvc_srvsvc_NetSrvInfo101_comment);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo101_comment_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSrvInfo101_comment, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo101(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo101);
	}

	offset = srvsvc_dissect_element_NetSrvInfo101_platform_id(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo101_server_name(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo101_version_major(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo101_version_minor(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo101_server_type(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo101_comment(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	srvsvc_PlatformId platform_id; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *server_name; */
/* IDL: 	uint32 version_major; */
/* IDL: 	uint32 version_minor; */
/* IDL: 	svcctl_ServerType server_type; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *comment; */
/* IDL: 	uint32 users; */
/* IDL: 	uint32 disc; */
/* IDL: 	uint32 hidden; */
/* IDL: 	uint32 announce; */
/* IDL: 	uint32 anndelta; */
/* IDL: 	uint32 licenses; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *userpath; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo102_platform_id(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_enum_PlatformId(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo102_platform_id, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo102_server_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo102_server_name_, NDR_POINTER_UNIQUE, "Pointer to Server Name (uint16)",hf_srvsvc_srvsvc_NetSrvInfo102_server_name);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo102_server_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSrvInfo102_server_name, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo102_version_major(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo102_version_major, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo102_version_minor(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo102_version_minor, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo102_comment(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo102_comment_, NDR_POINTER_UNIQUE, "Pointer to Comment (uint16)",hf_srvsvc_srvsvc_NetSrvInfo102_comment);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo102_comment_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSrvInfo102_comment, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo102_users(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo102_users, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo102_disc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo102_disc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo102_hidden(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo102_hidden, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo102_announce(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo102_announce, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo102_anndelta(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo102_anndelta, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo102_licenses(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo102_licenses, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo102_userpath(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo102_userpath_, NDR_POINTER_UNIQUE, "Pointer to Userpath (uint16)",hf_srvsvc_srvsvc_NetSrvInfo102_userpath);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo102_userpath_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSrvInfo102_userpath, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo102(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo102);
	}

	offset = srvsvc_dissect_element_NetSrvInfo102_platform_id(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo102_server_name(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo102_version_major(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo102_version_minor(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo102_server_type(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo102_comment(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo102_users(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo102_disc(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo102_hidden(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo102_announce(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo102_anndelta(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo102_licenses(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo102_userpath(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 ulist_mtime; */
/* IDL: 	uint32 glist_mtime; */
/* IDL: 	uint32 alist_mtime; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *alerts; */
/* IDL: 	uint32 security; */
/* IDL: 	uint32 numadmin; */
/* IDL: 	uint32 lanmask; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *guestaccount; */
/* IDL: 	uint32 chdevs; */
/* IDL: 	uint32 chdevqs; */
/* IDL: 	uint32 chdevjobs; */
/* IDL: 	uint32 connections; */
/* IDL: 	uint32 shares; */
/* IDL: 	uint32 openfiles; */
/* IDL: 	uint32 sessopen; */
/* IDL: 	uint32 sesssvc; */
/* IDL: 	uint32 sessreqs; */
/* IDL: 	uint32 opensearch; */
/* IDL: 	uint32 activelocks; */
/* IDL: 	uint32 sizereqbufs; */
/* IDL: 	uint32 numbigbufs; */
/* IDL: 	uint32 numfiletasks; */
/* IDL: 	uint32 alertsched; */
/* IDL: 	uint32 erroralert; */
/* IDL: 	uint32 logonalert; */
/* IDL: 	uint32 accessalert; */
/* IDL: 	uint32 diskalert; */
/* IDL: 	uint32 netioalert; */
/* IDL: 	uint32 maxaudits; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *srvheuristics; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo402_ulist_mtime(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo402_ulist_mtime, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_glist_mtime(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo402_glist_mtime, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_alist_mtime(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo402_alist_mtime, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_alerts(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo402_alerts_, NDR_POINTER_UNIQUE, "Pointer to Alerts (uint16)",hf_srvsvc_srvsvc_NetSrvInfo402_alerts);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_alerts_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSrvInfo402_alerts, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_security(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo402_security, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_numadmin(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo402_numadmin, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_lanmask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo402_lanmask, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_guestaccount(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo402_guestaccount_, NDR_POINTER_UNIQUE, "Pointer to Guestaccount (uint16)",hf_srvsvc_srvsvc_NetSrvInfo402_guestaccount);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_guestaccount_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSrvInfo402_guestaccount, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_chdevs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo402_chdevs, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_chdevqs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo402_chdevqs, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_chdevjobs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo402_chdevjobs, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_connections(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo402_connections, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_shares(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo402_shares, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_openfiles(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo402_openfiles, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_sessopen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo402_sessopen, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_sesssvc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo402_sesssvc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_sessreqs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo402_sessreqs, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_opensearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo402_opensearch, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_activelocks(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo402_activelocks, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_sizereqbufs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo402_sizereqbufs, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_numbigbufs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo402_numbigbufs, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_numfiletasks(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo402_numfiletasks, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_alertsched(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo402_alertsched, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_erroralert(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo402_erroralert, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_logonalert(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo402_logonalert, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_accessalert(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo402_accessalert, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_diskalert(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo402_diskalert, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_netioalert(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo402_netioalert, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_maxaudits(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo402_maxaudits, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_srvheuristics(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo402_srvheuristics_, NDR_POINTER_UNIQUE, "Pointer to Srvheuristics (uint16)",hf_srvsvc_srvsvc_NetSrvInfo402_srvheuristics);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo402_srvheuristics_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSrvInfo402_srvheuristics, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo402(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo402);
	}

	offset = srvsvc_dissect_element_NetSrvInfo402_ulist_mtime(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_glist_mtime(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_alist_mtime(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_alerts(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_security(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_numadmin(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_lanmask(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_guestaccount(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_chdevs(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_chdevqs(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_chdevjobs(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_connections(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_shares(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_openfiles(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_sessopen(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_sesssvc(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_sessreqs(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_opensearch(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_activelocks(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_sizereqbufs(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_numbigbufs(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_numfiletasks(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_alertsched(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_erroralert(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_logonalert(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_accessalert(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_diskalert(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_netioalert(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_maxaudits(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo402_srvheuristics(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 ulist_mtime; */
/* IDL: 	uint32 glist_mtime; */
/* IDL: 	uint32 alist_mtime; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *alerts; */
/* IDL: 	uint32 security; */
/* IDL: 	uint32 numadmin; */
/* IDL: 	uint32 lanmask; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *guestaccount; */
/* IDL: 	uint32 chdevs; */
/* IDL: 	uint32 chdevqs; */
/* IDL: 	uint32 chdevjobs; */
/* IDL: 	uint32 connections; */
/* IDL: 	uint32 shares; */
/* IDL: 	uint32 openfiles; */
/* IDL: 	uint32 sessopen; */
/* IDL: 	uint32 sesssvc; */
/* IDL: 	uint32 sessreqs; */
/* IDL: 	uint32 opensearch; */
/* IDL: 	uint32 activelocks; */
/* IDL: 	uint32 sizereqbufs; */
/* IDL: 	uint32 numbigbufs; */
/* IDL: 	uint32 numfiletasks; */
/* IDL: 	uint32 alertsched; */
/* IDL: 	uint32 eroralert; */
/* IDL: 	uint32 logonalert; */
/* IDL: 	uint32 accessalert; */
/* IDL: 	uint32 diskalert; */
/* IDL: 	uint32 netioalert; */
/* IDL: 	uint32 maxaudits; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *srvheuristics; */
/* IDL: 	uint32 auditedevents; */
/* IDL: 	uint32 auditprofile; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *autopath; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo403_ulist_mtime(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_ulist_mtime, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_glist_mtime(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_glist_mtime, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_alist_mtime(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_alist_mtime, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_alerts(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo403_alerts_, NDR_POINTER_UNIQUE, "Pointer to Alerts (uint16)",hf_srvsvc_srvsvc_NetSrvInfo403_alerts);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_alerts_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSrvInfo403_alerts, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_security(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_security, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_numadmin(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_numadmin, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_lanmask(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_lanmask, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_guestaccount(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo403_guestaccount_, NDR_POINTER_UNIQUE, "Pointer to Guestaccount (uint16)",hf_srvsvc_srvsvc_NetSrvInfo403_guestaccount);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_guestaccount_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSrvInfo403_guestaccount, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_chdevs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_chdevs, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_chdevqs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_chdevqs, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_chdevjobs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_chdevjobs, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_connections(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_connections, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_shares(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_shares, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_openfiles(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_openfiles, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_sessopen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_sessopen, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_sesssvc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_sesssvc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_sessreqs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_sessreqs, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_opensearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_opensearch, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_activelocks(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_activelocks, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_sizereqbufs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_sizereqbufs, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_numbigbufs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_numbigbufs, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_numfiletasks(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_numfiletasks, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_alertsched(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_alertsched, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_eroralert(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_eroralert, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_logonalert(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_logonalert, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_accessalert(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_accessalert, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_diskalert(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_diskalert, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_netioalert(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_netioalert, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_maxaudits(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_maxaudits, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_srvheuristics(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo403_srvheuristics_, NDR_POINTER_UNIQUE, "Pointer to Srvheuristics (uint16)",hf_srvsvc_srvsvc_NetSrvInfo403_srvheuristics);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_srvheuristics_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSrvInfo403_srvheuristics, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_auditedevents(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_auditedevents, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_auditprofile(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo403_auditprofile, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_autopath(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo403_autopath_, NDR_POINTER_UNIQUE, "Pointer to Autopath (uint16)",hf_srvsvc_srvsvc_NetSrvInfo403_autopath);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo403_autopath_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSrvInfo403_autopath, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo403(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo403);
	}

	offset = srvsvc_dissect_element_NetSrvInfo403_ulist_mtime(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_glist_mtime(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_alist_mtime(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_alerts(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_security(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_numadmin(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_lanmask(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_guestaccount(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_chdevs(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_chdevqs(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_chdevjobs(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_connections(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_shares(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_openfiles(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_sessopen(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_sesssvc(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_sessreqs(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_opensearch(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_activelocks(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_sizereqbufs(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_numbigbufs(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_numfiletasks(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_alertsched(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_eroralert(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_logonalert(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_accessalert(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_diskalert(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_netioalert(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_maxaudits(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_srvheuristics(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_auditedevents(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_auditprofile(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo403_autopath(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 sessopen; */
/* IDL: 	uint32 sesssvc; */
/* IDL: 	uint32 opensearch; */
/* IDL: 	uint32 sizereqbufs; */
/* IDL: 	uint32 initworkitems; */
/* IDL: 	uint32 maxworkitems; */
/* IDL: 	uint32 rawworkitems; */
/* IDL: 	uint32 irpstacksize; */
/* IDL: 	uint32 maxrawbuflen; */
/* IDL: 	uint32 sessusers; */
/* IDL: 	uint32 sessconns; */
/* IDL: 	uint32 maxpagedmemoryusage; */
/* IDL: 	uint32 maxnonpagedmemoryusage; */
/* IDL: 	uint32 enablesoftcompat; */
/* IDL: 	uint32 enableforcedlogoff; */
/* IDL: 	uint32 timesource; */
/* IDL: 	uint32 acceptdownlevelapis; */
/* IDL: 	uint32 lmannounce; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo502_sessopen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo502_sessopen, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo502_sesssvc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo502_sesssvc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo502_opensearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo502_opensearch, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo502_sizereqbufs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo502_sizereqbufs, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo502_initworkitems(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo502_initworkitems, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo502_maxworkitems(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo502_maxworkitems, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo502_rawworkitems(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo502_rawworkitems, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo502_irpstacksize(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo502_irpstacksize, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo502_maxrawbuflen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo502_maxrawbuflen, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo502_sessusers(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo502_sessusers, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo502_sessconns(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo502_sessconns, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo502_maxpagedmemoryusage(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo502_maxpagedmemoryusage, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo502_maxnonpagedmemoryusage(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo502_maxnonpagedmemoryusage, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo502_enablesoftcompat(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo502_enablesoftcompat, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo502_enableforcedlogoff(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo502_enableforcedlogoff, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo502_timesource(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo502_timesource, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo502_acceptdownlevelapis(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo502_acceptdownlevelapis, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo502_lmannounce(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo502_lmannounce, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo502(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo502);
	}

	offset = srvsvc_dissect_element_NetSrvInfo502_sessopen(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo502_sesssvc(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo502_opensearch(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo502_sizereqbufs(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo502_initworkitems(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo502_maxworkitems(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo502_rawworkitems(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo502_irpstacksize(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo502_maxrawbuflen(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo502_sessusers(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo502_sessconns(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo502_maxpagedmemoryusage(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo502_maxnonpagedmemoryusage(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo502_enablesoftcompat(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo502_enableforcedlogoff(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo502_timesource(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo502_acceptdownlevelapis(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo502_lmannounce(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 sessopen; */
/* IDL: 	uint32 sesssvc; */
/* IDL: 	uint32 opensearch; */
/* IDL: 	uint32 sizereqbufs; */
/* IDL: 	uint32 initworkitems; */
/* IDL: 	uint32 maxworkitems; */
/* IDL: 	uint32 rawworkitems; */
/* IDL: 	uint32 irpstacksize; */
/* IDL: 	uint32 maxrawbuflen; */
/* IDL: 	uint32 sessusers; */
/* IDL: 	uint32 sessconns; */
/* IDL: 	uint32 maxpagedmemoryusage; */
/* IDL: 	uint32 maxnonpagedmemoryusage; */
/* IDL: 	uint32 enablesoftcompat; */
/* IDL: 	uint32 enableforcedlogoff; */
/* IDL: 	uint32 timesource; */
/* IDL: 	uint32 acceptdownlevelapis; */
/* IDL: 	uint32 lmannounce; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *domain; */
/* IDL: 	uint32 maxcopyreadlen; */
/* IDL: 	uint32 maxcopywritelen; */
/* IDL: 	uint32 minkeepsearch; */
/* IDL: 	uint32 maxkeepsearch; */
/* IDL: 	uint32 minkeepcomplsearch; */
/* IDL: 	uint32 maxkeepcomplsearch; */
/* IDL: 	uint32 threadcountadd; */
/* IDL: 	uint32 numlockthreads; */
/* IDL: 	uint32 scavtimeout; */
/* IDL: 	uint32 minrcvqueue; */
/* IDL: 	uint32 minfreeworkitems; */
/* IDL: 	uint32 xactmemsize; */
/* IDL: 	uint32 threadpriority; */
/* IDL: 	uint32 maxmpxct; */
/* IDL: 	uint32 oplockbreakwait; */
/* IDL: 	uint32 oplockbreakresponsewait; */
/* IDL: 	uint32 enableoplocks; */
/* IDL: 	uint32 enableoplockforceclose; */
/* IDL: 	uint32 enablefcbopens; */
/* IDL: 	uint32 enableraw; */
/* IDL: 	uint32 enablesharednetdrives; */
/* IDL: 	uint32 minfreeconnections; */
/* IDL: 	uint32 maxfreeconnections; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo503_sessopen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_sessopen, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_sesssvc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_sesssvc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_opensearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_opensearch, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_sizereqbufs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_sizereqbufs, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_initworkitems(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_initworkitems, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_maxworkitems(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_maxworkitems, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_rawworkitems(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_rawworkitems, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_irpstacksize(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_irpstacksize, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_maxrawbuflen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_maxrawbuflen, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_sessusers(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_sessusers, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_sessconns(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_sessconns, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_maxpagedmemoryusage(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_maxpagedmemoryusage, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_maxnonpagedmemoryusage(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_maxnonpagedmemoryusage, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_enablesoftcompat(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_enablesoftcompat, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_enableforcedlogoff(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_enableforcedlogoff, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_timesource(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_timesource, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_acceptdownlevelapis(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_acceptdownlevelapis, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_lmannounce(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_lmannounce, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_domain(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo503_domain_, NDR_POINTER_UNIQUE, "Pointer to Domain (uint16)",hf_srvsvc_srvsvc_NetSrvInfo503_domain);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_domain_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSrvInfo503_domain, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_maxcopyreadlen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_maxcopyreadlen, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_maxcopywritelen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_maxcopywritelen, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_minkeepsearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_minkeepsearch, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_maxkeepsearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_maxkeepsearch, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_minkeepcomplsearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_minkeepcomplsearch, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_maxkeepcomplsearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_maxkeepcomplsearch, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_threadcountadd(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_threadcountadd, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_numlockthreads(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_numlockthreads, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_scavtimeout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_scavtimeout, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_minrcvqueue(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_minrcvqueue, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_minfreeworkitems(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_minfreeworkitems, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_xactmemsize(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_xactmemsize, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_threadpriority(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_threadpriority, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_maxmpxct(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_maxmpxct, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_oplockbreakwait(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_oplockbreakwait, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_oplockbreakresponsewait(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_oplockbreakresponsewait, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_enableoplocks(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_enableoplocks, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_enableoplockforceclose(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_enableoplockforceclose, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_enablefcbopens(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_enablefcbopens, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_enableraw(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_enableraw, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_enablesharednetdrives(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_enablesharednetdrives, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_minfreeconnections(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_minfreeconnections, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo503_maxfreeconnections(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo503_maxfreeconnections, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo503(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo503);
	}

	offset = srvsvc_dissect_element_NetSrvInfo503_sessopen(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_sesssvc(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_opensearch(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_sizereqbufs(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_initworkitems(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_maxworkitems(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_rawworkitems(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_irpstacksize(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_maxrawbuflen(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_sessusers(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_sessconns(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_maxpagedmemoryusage(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_maxnonpagedmemoryusage(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_enablesoftcompat(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_enableforcedlogoff(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_timesource(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_acceptdownlevelapis(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_lmannounce(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_domain(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_maxcopyreadlen(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_maxcopywritelen(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_minkeepsearch(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_maxkeepsearch(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_minkeepcomplsearch(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_maxkeepcomplsearch(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_threadcountadd(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_numlockthreads(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_scavtimeout(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_minrcvqueue(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_minfreeworkitems(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_xactmemsize(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_threadpriority(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_maxmpxct(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_oplockbreakwait(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_oplockbreakresponsewait(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_enableoplocks(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_enableoplockforceclose(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_enablefcbopens(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_enableraw(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_enablesharednetdrives(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_minfreeconnections(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo503_maxfreeconnections(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 sessopen; */
/* IDL: 	uint32 sesssvc; */
/* IDL: 	uint32 opensearch; */
/* IDL: 	uint32 sizereqbufs; */
/* IDL: 	uint32 initworkitems; */
/* IDL: 	uint32 maxworkitems; */
/* IDL: 	uint32 rawworkitems; */
/* IDL: 	uint32 irpstacksize; */
/* IDL: 	uint32 maxrawbuflen; */
/* IDL: 	uint32 sessusers; */
/* IDL: 	uint32 sessconns; */
/* IDL: 	uint32 maxpagedmemoryusage; */
/* IDL: 	uint32 maxnonpagedmemoryusage; */
/* IDL: 	uint32 enablesoftcompat; */
/* IDL: 	uint32 enableforcedlogoff; */
/* IDL: 	uint32 timesource; */
/* IDL: 	uint32 acceptdownlevelapis; */
/* IDL: 	uint32 lmannounce; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *domain; */
/* IDL: 	uint32 maxcopyreadlen; */
/* IDL: 	uint32 maxcopywritelen; */
/* IDL: 	uint32 minkeepsearch; */
/* IDL: 	uint32 minkeepcomplsearch; */
/* IDL: 	uint32 maxkeepcomplsearch; */
/* IDL: 	uint32 threadcountadd; */
/* IDL: 	uint32 numlockthreads; */
/* IDL: 	uint32 scavtimeout; */
/* IDL: 	uint32 minrcvqueue; */
/* IDL: 	uint32 minfreeworkitems; */
/* IDL: 	uint32 xactmemsize; */
/* IDL: 	uint32 threadpriority; */
/* IDL: 	uint32 maxmpxct; */
/* IDL: 	uint32 oplockbreakwait; */
/* IDL: 	uint32 oplockbreakresponsewait; */
/* IDL: 	uint32 enableoplocks; */
/* IDL: 	uint32 enableoplockforceclose; */
/* IDL: 	uint32 enablefcbopens; */
/* IDL: 	uint32 enableraw; */
/* IDL: 	uint32 enablesharednetdrives; */
/* IDL: 	uint32 minfreeconnections; */
/* IDL: 	uint32 maxfreeconnections; */
/* IDL: 	uint32 initsesstable; */
/* IDL: 	uint32 initconntable; */
/* IDL: 	uint32 initfiletable; */
/* IDL: 	uint32 initsearchtable; */
/* IDL: 	uint32 alertsched; */
/* IDL: 	uint32 errortreshold; */
/* IDL: 	uint32 networkerrortreshold; */
/* IDL: 	uint32 diskspacetreshold; */
/* IDL: 	uint32 reserved; */
/* IDL: 	uint32 maxlinkdelay; */
/* IDL: 	uint32 minlinkthroughput; */
/* IDL: 	uint32 linkinfovalidtime; */
/* IDL: 	uint32 scavqosinfoupdatetime; */
/* IDL: 	uint32 maxworkitemidletime; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo599_sessopen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_sessopen, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_sesssvc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_sesssvc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_opensearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_opensearch, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_sizereqbufs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_sizereqbufs, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_initworkitems(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_initworkitems, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_maxworkitems(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_maxworkitems, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_rawworkitems(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_rawworkitems, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_irpstacksize(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_irpstacksize, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_maxrawbuflen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_maxrawbuflen, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_sessusers(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_sessusers, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_sessconns(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_sessconns, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_maxpagedmemoryusage(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_maxpagedmemoryusage, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_maxnonpagedmemoryusage(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_maxnonpagedmemoryusage, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_enablesoftcompat(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_enablesoftcompat, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_enableforcedlogoff(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_enableforcedlogoff, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_timesource(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_timesource, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_acceptdownlevelapis(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_acceptdownlevelapis, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_lmannounce(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_lmannounce, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_domain(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo599_domain_, NDR_POINTER_UNIQUE, "Pointer to Domain (uint16)",hf_srvsvc_srvsvc_NetSrvInfo599_domain);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_domain_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSrvInfo599_domain, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_maxcopyreadlen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_maxcopyreadlen, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_maxcopywritelen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_maxcopywritelen, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_minkeepsearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_minkeepsearch, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_minkeepcomplsearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_minkeepcomplsearch, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_maxkeepcomplsearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_maxkeepcomplsearch, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_threadcountadd(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_threadcountadd, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_numlockthreads(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_numlockthreads, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_scavtimeout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_scavtimeout, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_minrcvqueue(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_minrcvqueue, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_minfreeworkitems(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_minfreeworkitems, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_xactmemsize(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_xactmemsize, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_threadpriority(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_threadpriority, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_maxmpxct(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_maxmpxct, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_oplockbreakwait(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_oplockbreakwait, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_oplockbreakresponsewait(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_oplockbreakresponsewait, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_enableoplocks(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_enableoplocks, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_enableoplockforceclose(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_enableoplockforceclose, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_enablefcbopens(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_enablefcbopens, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_enableraw(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_enableraw, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_enablesharednetdrives(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_enablesharednetdrives, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_minfreeconnections(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_minfreeconnections, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_maxfreeconnections(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_maxfreeconnections, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_initsesstable(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_initsesstable, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_initconntable(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_initconntable, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_initfiletable(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_initfiletable, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_initsearchtable(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_initsearchtable, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_alertsched(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_alertsched, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_errortreshold(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_errortreshold, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_networkerrortreshold(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_networkerrortreshold, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_diskspacetreshold(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_diskspacetreshold, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_reserved(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_reserved, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_maxlinkdelay(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_maxlinkdelay, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_minlinkthroughput(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_minlinkthroughput, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_linkinfovalidtime(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_linkinfovalidtime, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_scavqosinfoupdatetime(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_scavqosinfoupdatetime, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo599_maxworkitemidletime(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo599_maxworkitemidletime, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo599(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo599);
	}

	offset = srvsvc_dissect_element_NetSrvInfo599_sessopen(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_sesssvc(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_opensearch(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_sizereqbufs(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_initworkitems(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_maxworkitems(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_rawworkitems(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_irpstacksize(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_maxrawbuflen(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_sessusers(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_sessconns(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_maxpagedmemoryusage(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_maxnonpagedmemoryusage(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_enablesoftcompat(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_enableforcedlogoff(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_timesource(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_acceptdownlevelapis(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_lmannounce(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_domain(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_maxcopyreadlen(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_maxcopywritelen(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_minkeepsearch(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_minkeepcomplsearch(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_maxkeepcomplsearch(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_threadcountadd(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_numlockthreads(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_scavtimeout(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_minrcvqueue(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_minfreeworkitems(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_xactmemsize(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_threadpriority(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_maxmpxct(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_oplockbreakwait(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_oplockbreakresponsewait(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_enableoplocks(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_enableoplockforceclose(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_enablefcbopens(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_enableraw(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_enablesharednetdrives(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_minfreeconnections(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_maxfreeconnections(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_initsesstable(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_initconntable(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_initfiletable(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_initsearchtable(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_alertsched(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_errortreshold(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_networkerrortreshold(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_diskspacetreshold(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_reserved(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_maxlinkdelay(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_minlinkthroughput(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_linkinfovalidtime(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_scavqosinfoupdatetime(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetSrvInfo599_maxworkitemidletime(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *comment; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1005_comment(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo1005_comment_, NDR_POINTER_UNIQUE, "Pointer to Comment (uint16)",hf_srvsvc_srvsvc_NetSrvInfo1005_comment);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo1005_comment_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSrvInfo1005_comment, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1005(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1005);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1005_comment(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 disc; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1010_disc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1010_disc, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1010(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1010);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1010_disc(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 hidden; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1016_hidden(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1016_hidden, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1016(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1016);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1016_hidden(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 announce; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1017_announce(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1017_announce, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1017(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1017);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1017_announce(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 anndelta; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1018_anndelta(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1018_anndelta, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1018(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1018);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1018_anndelta(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 users; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1107_users(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1107_users, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1107(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1107);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1107_users(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 sessopens; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1501_sessopens(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1501_sessopens, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1501(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1501);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1501_sessopens(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 sessvcs; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1502_sessvcs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1502_sessvcs, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1502(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1502);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1502_sessvcs(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 opensearch; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1503_opensearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1503_opensearch, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1503(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1503);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1503_opensearch(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 maxworkitems; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1506_maxworkitems(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1506_maxworkitems, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1506(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1506);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1506_maxworkitems(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 maxrawbuflen; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1509_maxrawbuflen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1509_maxrawbuflen, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1509(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1509);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1509_maxrawbuflen(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 sessusers; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1510_sessusers(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1510_sessusers, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1510(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1510);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1510_sessusers(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 sesscons; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1511_sesscons(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1511_sesscons, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1511(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1511);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1511_sesscons(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 maxnonpagedmemoryusage; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1512_maxnonpagedmemoryusage(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1512_maxnonpagedmemoryusage, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1512(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1512);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1512_maxnonpagedmemoryusage(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 maxpagedmemoryusage; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1513_maxpagedmemoryusage(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1513_maxpagedmemoryusage, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1513(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1513);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1513_maxpagedmemoryusage(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 enablesoftcompat; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1514_enablesoftcompat(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1514_enablesoftcompat, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1514(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1514);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1514_enablesoftcompat(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 enableforcedlogoff; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1515_enableforcedlogoff(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1515_enableforcedlogoff, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1515(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1515);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1515_enableforcedlogoff(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 timesource; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1516_timesource(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1516_timesource, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1516(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1516);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1516_timesource(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 lmannounce; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1518_lmannounce(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1518_lmannounce, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1518(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1518);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1518_lmannounce(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 maxcopyreadlen; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1520_maxcopyreadlen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1520_maxcopyreadlen, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1520(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1520);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1520_maxcopyreadlen(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 maxcopywritelen; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1521_maxcopywritelen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1521_maxcopywritelen, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1521(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1521);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1521_maxcopywritelen(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 minkeepsearch; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1522_minkeepsearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1522_minkeepsearch, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1522(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1522);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1522_minkeepsearch(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 maxkeepsearch; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1523_maxkeepsearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1523_maxkeepsearch, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1523(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1523);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1523_maxkeepsearch(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 minkeepcomplsearch; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1524_minkeepcomplsearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1524_minkeepcomplsearch, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1524(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1524);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1524_minkeepcomplsearch(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 maxkeepcomplsearch; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1525_maxkeepcomplsearch(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1525_maxkeepcomplsearch, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1525(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1525);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1525_maxkeepcomplsearch(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 scavtimeout; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1528_scavtimeout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1528_scavtimeout, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1528(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1528);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1528_scavtimeout(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 minrcvqueue; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1529_minrcvqueue(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1529_minrcvqueue, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1529(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1529);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1529_minrcvqueue(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 minfreeworkitems; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1530_minfreeworkitems(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1530_minfreeworkitems, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1530(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1530);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1530_minfreeworkitems(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 maxmpxct; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1533_maxmpxct(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1533_maxmpxct, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1533(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1533);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1533_maxmpxct(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 oplockbreakwait; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1534_oplockbreakwait(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1534_oplockbreakwait, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1534(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1534);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1534_oplockbreakwait(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 oplockbreakresponsewait; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1535_oplockbreakresponsewait(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1535_oplockbreakresponsewait, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1535(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1535);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1535_oplockbreakresponsewait(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 enableoplocks; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1536_enableoplocks(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1536_enableoplocks, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1536(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1536);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1536_enableoplocks(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 enableoplockforceclose; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1537_enableoplockforceclose(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1537_enableoplockforceclose, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1537(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1537);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1537_enableoplockforceclose(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 enablefcbopens; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1538_enablefcbopens(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1538_enablefcbopens, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1538(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1538);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1538_enablefcbopens(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 enableraw; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1539_enableraw(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1539_enableraw, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1539(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1539);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1539_enableraw(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 enablesharednetdrives; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1540_enablesharednetdrives(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1540_enablesharednetdrives, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1540(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1540);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1540_enablesharednetdrives(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 minfreeconnections; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1541_minfreeconnections(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1541_minfreeconnections, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1541(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1541);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1541_minfreeconnections(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 maxfreeconnections; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1542_maxfreeconnections(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1542_maxfreeconnections, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1542(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1542);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1542_maxfreeconnections(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 initsesstable; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1543_initsesstable(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1543_initsesstable, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1543(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1543);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1543_initsesstable(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 initconntable; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1544_initconntable(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1544_initconntable, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1544(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1544);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1544_initconntable(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 initfiletable; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1545_initfiletable(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1545_initfiletable, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1545(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1545);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1545_initfiletable(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 initsearchtable; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1546_initsearchtable(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1546_initsearchtable, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1546(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1546);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1546_initsearchtable(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 alertsched; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1547_alertsched(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1547_alertsched, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1547(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1547);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1547_alertsched(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 errortreshold; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1548_errortreshold(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1548_errortreshold, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1548(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1548);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1548_errortreshold(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 networkerrortreshold; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1549_networkerrortreshold(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1549_networkerrortreshold, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1549(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1549);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1549_networkerrortreshold(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 diskspacetreshold; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1550_diskspacetreshold(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1550_diskspacetreshold, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1550(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1550);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1550_diskspacetreshold(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 maxlinkdelay; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1552_maxlinkdelay(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1552_maxlinkdelay, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1552(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1552);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1552_maxlinkdelay(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 minlinkthroughput; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1553_minlinkthroughput(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1553_minlinkthroughput, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1553(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1553);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1553_minlinkthroughput(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 linkinfovalidtime; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1554_linkinfovalidtime(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1554_linkinfovalidtime, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1554(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1554);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1554_linkinfovalidtime(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 scavqosinfoupdatetime; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1555_scavqosinfoupdatetime(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1555_scavqosinfoupdatetime, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1555(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1555);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1555_scavqosinfoupdatetime(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 maxworkitemidletime; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo1556_maxworkitemidletime(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvInfo1556_maxworkitemidletime, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetSrvInfo1556(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo1556);
	}

	offset = srvsvc_dissect_element_NetSrvInfo1556_maxworkitemidletime(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: union { */
/* IDL: [case(100)] [unique(1)] [case(100)] srvsvc_NetSrvInfo100 *info100; */
/* IDL: [case(101)] [unique(1)] [case(101)] srvsvc_NetSrvInfo101 *info101; */
/* IDL: [case(102)] [unique(1)] [case(102)] srvsvc_NetSrvInfo102 *info102; */
/* IDL: [case(402)] [unique(1)] [case(402)] srvsvc_NetSrvInfo402 *info402; */
/* IDL: [case(403)] [unique(1)] [case(403)] srvsvc_NetSrvInfo403 *info403; */
/* IDL: [case(502)] [unique(1)] [case(502)] srvsvc_NetSrvInfo502 *info502; */
/* IDL: [case(503)] [unique(1)] [case(503)] srvsvc_NetSrvInfo503 *info503; */
/* IDL: [case(599)] [unique(1)] [case(599)] srvsvc_NetSrvInfo599 *info599; */
/* IDL: [case(1005)] [unique(1)] [case(1005)] srvsvc_NetSrvInfo1005 *info1005; */
/* IDL: [case(1010)] [unique(1)] [case(1010)] srvsvc_NetSrvInfo1010 *info1010; */
/* IDL: [case(1016)] [unique(1)] [case(1016)] srvsvc_NetSrvInfo1016 *info1016; */
/* IDL: [case(1017)] [unique(1)] [case(1017)] srvsvc_NetSrvInfo1017 *info1017; */
/* IDL: [case(1018)] [unique(1)] [case(1018)] srvsvc_NetSrvInfo1018 *info1018; */
/* IDL: [case(1107)] [unique(1)] [case(1107)] srvsvc_NetSrvInfo1107 *info1107; */
/* IDL: [case(1501)] [unique(1)] [case(1501)] srvsvc_NetSrvInfo1501 *info1501; */
/* IDL: [case(1502)] [unique(1)] [case(1502)] srvsvc_NetSrvInfo1502 *info1502; */
/* IDL: [case(1503)] [unique(1)] [case(1503)] srvsvc_NetSrvInfo1503 *info1503; */
/* IDL: [case(1506)] [unique(1)] [case(1506)] srvsvc_NetSrvInfo1506 *info1506; */
/* IDL: [case(1509)] [unique(1)] [case(1509)] srvsvc_NetSrvInfo1509 *info1509; */
/* IDL: [case(1510)] [unique(1)] [case(1510)] srvsvc_NetSrvInfo1510 *info1510; */
/* IDL: [case(1511)] [unique(1)] [case(1511)] srvsvc_NetSrvInfo1511 *info1511; */
/* IDL: [case(1512)] [unique(1)] [case(1512)] srvsvc_NetSrvInfo1512 *info1512; */
/* IDL: [case(1513)] [unique(1)] [case(1513)] srvsvc_NetSrvInfo1513 *info1513; */
/* IDL: [case(1514)] [unique(1)] [case(1514)] srvsvc_NetSrvInfo1514 *info1514; */
/* IDL: [case(1515)] [unique(1)] [case(1515)] srvsvc_NetSrvInfo1515 *info1515; */
/* IDL: [case(1516)] [unique(1)] [case(1516)] srvsvc_NetSrvInfo1516 *info1516; */
/* IDL: [case(1518)] [unique(1)] [case(1518)] srvsvc_NetSrvInfo1518 *info1518; */
/* IDL: [case(1520)] [unique(1)] [case(1520)] srvsvc_NetSrvInfo1520 *info1520; */
/* IDL: [case(1521)] [unique(1)] [case(1521)] srvsvc_NetSrvInfo1521 *info1521; */
/* IDL: [case(1522)] [unique(1)] [case(1522)] srvsvc_NetSrvInfo1522 *info1522; */
/* IDL: [case(1523)] [unique(1)] [case(1523)] srvsvc_NetSrvInfo1523 *info1523; */
/* IDL: [case(1524)] [unique(1)] [case(1524)] srvsvc_NetSrvInfo1524 *info1524; */
/* IDL: [case(1525)] [unique(1)] [case(1525)] srvsvc_NetSrvInfo1525 *info1525; */
/* IDL: [case(1528)] [unique(1)] [case(1528)] srvsvc_NetSrvInfo1528 *info1528; */
/* IDL: [case(1529)] [unique(1)] [case(1529)] srvsvc_NetSrvInfo1529 *info1529; */
/* IDL: [case(1530)] [unique(1)] [case(1530)] srvsvc_NetSrvInfo1530 *info1530; */
/* IDL: [case(1533)] [unique(1)] [case(1533)] srvsvc_NetSrvInfo1533 *info1533; */
/* IDL: [case(1534)] [unique(1)] [case(1534)] srvsvc_NetSrvInfo1534 *info1534; */
/* IDL: [case(1535)] [unique(1)] [case(1535)] srvsvc_NetSrvInfo1535 *info1535; */
/* IDL: [case(1536)] [unique(1)] [case(1536)] srvsvc_NetSrvInfo1536 *info1536; */
/* IDL: [case(1537)] [unique(1)] [case(1537)] srvsvc_NetSrvInfo1537 *info1537; */
/* IDL: [case(1538)] [unique(1)] [case(1538)] srvsvc_NetSrvInfo1538 *info1538; */
/* IDL: [case(1539)] [unique(1)] [case(1539)] srvsvc_NetSrvInfo1539 *info1539; */
/* IDL: [case(1540)] [unique(1)] [case(1540)] srvsvc_NetSrvInfo1540 *info1540; */
/* IDL: [case(1541)] [unique(1)] [case(1541)] srvsvc_NetSrvInfo1541 *info1541; */
/* IDL: [case(1542)] [unique(1)] [case(1542)] srvsvc_NetSrvInfo1542 *info1542; */
/* IDL: [case(1543)] [unique(1)] [case(1543)] srvsvc_NetSrvInfo1543 *info1543; */
/* IDL: [case(1544)] [unique(1)] [case(1544)] srvsvc_NetSrvInfo1544 *info1544; */
/* IDL: [case(1545)] [unique(1)] [case(1545)] srvsvc_NetSrvInfo1545 *info1545; */
/* IDL: [case(1546)] [unique(1)] [case(1546)] srvsvc_NetSrvInfo1546 *info1546; */
/* IDL: [case(1547)] [unique(1)] [case(1547)] srvsvc_NetSrvInfo1547 *info1547; */
/* IDL: [case(1548)] [unique(1)] [case(1548)] srvsvc_NetSrvInfo1548 *info1548; */
/* IDL: [case(1549)] [unique(1)] [case(1549)] srvsvc_NetSrvInfo1549 *info1549; */
/* IDL: [case(1550)] [unique(1)] [case(1550)] srvsvc_NetSrvInfo1550 *info1550; */
/* IDL: [case(1552)] [unique(1)] [case(1552)] srvsvc_NetSrvInfo1552 *info1552; */
/* IDL: [case(1553)] [unique(1)] [case(1553)] srvsvc_NetSrvInfo1553 *info1553; */
/* IDL: [case(1554)] [unique(1)] [case(1554)] srvsvc_NetSrvInfo1554 *info1554; */
/* IDL: [case(1555)] [unique(1)] [case(1555)] srvsvc_NetSrvInfo1555 *info1555; */
/* IDL: [case(1556)] [unique(1)] [case(1556)] srvsvc_NetSrvInfo1556 *info1556; */
/* IDL: [default] ; */
/* IDL: } */

static int
srvsvc_dissect_element_NetSrvInfo_info100(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info100_, NDR_POINTER_UNIQUE, "Pointer to Info100 (srvsvc_NetSrvInfo100)",hf_srvsvc_srvsvc_NetSrvInfo_info100);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info100_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo100(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info100,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info101(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info101_, NDR_POINTER_UNIQUE, "Pointer to Info101 (srvsvc_NetSrvInfo101)",hf_srvsvc_srvsvc_NetSrvInfo_info101);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info101_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo101(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info101,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info102(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info102_, NDR_POINTER_UNIQUE, "Pointer to Info102 (srvsvc_NetSrvInfo102)",hf_srvsvc_srvsvc_NetSrvInfo_info102);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info102_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo102(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info102,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info402(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info402_, NDR_POINTER_UNIQUE, "Pointer to Info402 (srvsvc_NetSrvInfo402)",hf_srvsvc_srvsvc_NetSrvInfo_info402);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info402_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo402(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info402,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info403(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info403_, NDR_POINTER_UNIQUE, "Pointer to Info403 (srvsvc_NetSrvInfo403)",hf_srvsvc_srvsvc_NetSrvInfo_info403);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info403_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo403(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info403,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info502(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info502_, NDR_POINTER_UNIQUE, "Pointer to Info502 (srvsvc_NetSrvInfo502)",hf_srvsvc_srvsvc_NetSrvInfo_info502);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info502_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo502(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info502,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info503(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info503_, NDR_POINTER_UNIQUE, "Pointer to Info503 (srvsvc_NetSrvInfo503)",hf_srvsvc_srvsvc_NetSrvInfo_info503);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info503_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo503(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info503,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info599(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info599_, NDR_POINTER_UNIQUE, "Pointer to Info599 (srvsvc_NetSrvInfo599)",hf_srvsvc_srvsvc_NetSrvInfo_info599);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info599_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo599(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info599,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1005(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1005_, NDR_POINTER_UNIQUE, "Pointer to Info1005 (srvsvc_NetSrvInfo1005)",hf_srvsvc_srvsvc_NetSrvInfo_info1005);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1005_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1005(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1005,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1010(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1010_, NDR_POINTER_UNIQUE, "Pointer to Info1010 (srvsvc_NetSrvInfo1010)",hf_srvsvc_srvsvc_NetSrvInfo_info1010);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1010_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1010(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1010,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1016(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1016_, NDR_POINTER_UNIQUE, "Pointer to Info1016 (srvsvc_NetSrvInfo1016)",hf_srvsvc_srvsvc_NetSrvInfo_info1016);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1016_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1016(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1016,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1017(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1017_, NDR_POINTER_UNIQUE, "Pointer to Info1017 (srvsvc_NetSrvInfo1017)",hf_srvsvc_srvsvc_NetSrvInfo_info1017);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1017_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1017(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1017,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1018(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1018_, NDR_POINTER_UNIQUE, "Pointer to Info1018 (srvsvc_NetSrvInfo1018)",hf_srvsvc_srvsvc_NetSrvInfo_info1018);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1018_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1018(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1018,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1107(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1107_, NDR_POINTER_UNIQUE, "Pointer to Info1107 (srvsvc_NetSrvInfo1107)",hf_srvsvc_srvsvc_NetSrvInfo_info1107);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1107_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1107(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1107,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1501(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1501_, NDR_POINTER_UNIQUE, "Pointer to Info1501 (srvsvc_NetSrvInfo1501)",hf_srvsvc_srvsvc_NetSrvInfo_info1501);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1501_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1501(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1501,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1502(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1502_, NDR_POINTER_UNIQUE, "Pointer to Info1502 (srvsvc_NetSrvInfo1502)",hf_srvsvc_srvsvc_NetSrvInfo_info1502);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1502_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1502(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1502,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1503(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1503_, NDR_POINTER_UNIQUE, "Pointer to Info1503 (srvsvc_NetSrvInfo1503)",hf_srvsvc_srvsvc_NetSrvInfo_info1503);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1503_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1503(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1503,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1506(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1506_, NDR_POINTER_UNIQUE, "Pointer to Info1506 (srvsvc_NetSrvInfo1506)",hf_srvsvc_srvsvc_NetSrvInfo_info1506);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1506_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1506(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1506,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1509(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1509_, NDR_POINTER_UNIQUE, "Pointer to Info1509 (srvsvc_NetSrvInfo1509)",hf_srvsvc_srvsvc_NetSrvInfo_info1509);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1509_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1509(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1509,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1510(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1510_, NDR_POINTER_UNIQUE, "Pointer to Info1510 (srvsvc_NetSrvInfo1510)",hf_srvsvc_srvsvc_NetSrvInfo_info1510);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1510_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1510(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1510,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1511(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1511_, NDR_POINTER_UNIQUE, "Pointer to Info1511 (srvsvc_NetSrvInfo1511)",hf_srvsvc_srvsvc_NetSrvInfo_info1511);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1511_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1511(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1511,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1512(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1512_, NDR_POINTER_UNIQUE, "Pointer to Info1512 (srvsvc_NetSrvInfo1512)",hf_srvsvc_srvsvc_NetSrvInfo_info1512);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1512_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1512(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1512,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1513(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1513_, NDR_POINTER_UNIQUE, "Pointer to Info1513 (srvsvc_NetSrvInfo1513)",hf_srvsvc_srvsvc_NetSrvInfo_info1513);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1513_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1513(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1513,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1514(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1514_, NDR_POINTER_UNIQUE, "Pointer to Info1514 (srvsvc_NetSrvInfo1514)",hf_srvsvc_srvsvc_NetSrvInfo_info1514);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1514_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1514(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1514,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1515(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1515_, NDR_POINTER_UNIQUE, "Pointer to Info1515 (srvsvc_NetSrvInfo1515)",hf_srvsvc_srvsvc_NetSrvInfo_info1515);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1515_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1515(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1515,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1516(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1516_, NDR_POINTER_UNIQUE, "Pointer to Info1516 (srvsvc_NetSrvInfo1516)",hf_srvsvc_srvsvc_NetSrvInfo_info1516);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1516_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1516(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1516,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1518(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1518_, NDR_POINTER_UNIQUE, "Pointer to Info1518 (srvsvc_NetSrvInfo1518)",hf_srvsvc_srvsvc_NetSrvInfo_info1518);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1518_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1518(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1518,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1520(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1520_, NDR_POINTER_UNIQUE, "Pointer to Info1520 (srvsvc_NetSrvInfo1520)",hf_srvsvc_srvsvc_NetSrvInfo_info1520);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1520_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1520(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1520,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1521(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1521_, NDR_POINTER_UNIQUE, "Pointer to Info1521 (srvsvc_NetSrvInfo1521)",hf_srvsvc_srvsvc_NetSrvInfo_info1521);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1521_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1521(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1521,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1522(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1522_, NDR_POINTER_UNIQUE, "Pointer to Info1522 (srvsvc_NetSrvInfo1522)",hf_srvsvc_srvsvc_NetSrvInfo_info1522);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1522_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1522(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1522,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1523(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1523_, NDR_POINTER_UNIQUE, "Pointer to Info1523 (srvsvc_NetSrvInfo1523)",hf_srvsvc_srvsvc_NetSrvInfo_info1523);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1523_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1523(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1523,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1524(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1524_, NDR_POINTER_UNIQUE, "Pointer to Info1524 (srvsvc_NetSrvInfo1524)",hf_srvsvc_srvsvc_NetSrvInfo_info1524);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1524_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1524(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1524,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1525(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1525_, NDR_POINTER_UNIQUE, "Pointer to Info1525 (srvsvc_NetSrvInfo1525)",hf_srvsvc_srvsvc_NetSrvInfo_info1525);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1525_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1525(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1525,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1528(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1528_, NDR_POINTER_UNIQUE, "Pointer to Info1528 (srvsvc_NetSrvInfo1528)",hf_srvsvc_srvsvc_NetSrvInfo_info1528);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1528_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1528(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1528,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1529(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1529_, NDR_POINTER_UNIQUE, "Pointer to Info1529 (srvsvc_NetSrvInfo1529)",hf_srvsvc_srvsvc_NetSrvInfo_info1529);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1529_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1529(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1529,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1530(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1530_, NDR_POINTER_UNIQUE, "Pointer to Info1530 (srvsvc_NetSrvInfo1530)",hf_srvsvc_srvsvc_NetSrvInfo_info1530);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1530_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1530(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1530,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1533(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1533_, NDR_POINTER_UNIQUE, "Pointer to Info1533 (srvsvc_NetSrvInfo1533)",hf_srvsvc_srvsvc_NetSrvInfo_info1533);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1533_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1533(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1533,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1534(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1534_, NDR_POINTER_UNIQUE, "Pointer to Info1534 (srvsvc_NetSrvInfo1534)",hf_srvsvc_srvsvc_NetSrvInfo_info1534);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1534_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1534(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1534,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1535(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1535_, NDR_POINTER_UNIQUE, "Pointer to Info1535 (srvsvc_NetSrvInfo1535)",hf_srvsvc_srvsvc_NetSrvInfo_info1535);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1535_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1535(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1535,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1536(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1536_, NDR_POINTER_UNIQUE, "Pointer to Info1536 (srvsvc_NetSrvInfo1536)",hf_srvsvc_srvsvc_NetSrvInfo_info1536);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1536_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1536(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1536,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1537(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1537_, NDR_POINTER_UNIQUE, "Pointer to Info1537 (srvsvc_NetSrvInfo1537)",hf_srvsvc_srvsvc_NetSrvInfo_info1537);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1537_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1537(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1537,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1538(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1538_, NDR_POINTER_UNIQUE, "Pointer to Info1538 (srvsvc_NetSrvInfo1538)",hf_srvsvc_srvsvc_NetSrvInfo_info1538);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1538_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1538(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1538,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1539(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1539_, NDR_POINTER_UNIQUE, "Pointer to Info1539 (srvsvc_NetSrvInfo1539)",hf_srvsvc_srvsvc_NetSrvInfo_info1539);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1539_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1539(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1539,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1540(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1540_, NDR_POINTER_UNIQUE, "Pointer to Info1540 (srvsvc_NetSrvInfo1540)",hf_srvsvc_srvsvc_NetSrvInfo_info1540);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1540_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1540(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1540,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1541(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1541_, NDR_POINTER_UNIQUE, "Pointer to Info1541 (srvsvc_NetSrvInfo1541)",hf_srvsvc_srvsvc_NetSrvInfo_info1541);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1541_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1541(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1541,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1542(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1542_, NDR_POINTER_UNIQUE, "Pointer to Info1542 (srvsvc_NetSrvInfo1542)",hf_srvsvc_srvsvc_NetSrvInfo_info1542);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1542_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1542(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1542,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1543(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1543_, NDR_POINTER_UNIQUE, "Pointer to Info1543 (srvsvc_NetSrvInfo1543)",hf_srvsvc_srvsvc_NetSrvInfo_info1543);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1543_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1543(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1543,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1544(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1544_, NDR_POINTER_UNIQUE, "Pointer to Info1544 (srvsvc_NetSrvInfo1544)",hf_srvsvc_srvsvc_NetSrvInfo_info1544);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1544_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1544(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1544,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1545(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1545_, NDR_POINTER_UNIQUE, "Pointer to Info1545 (srvsvc_NetSrvInfo1545)",hf_srvsvc_srvsvc_NetSrvInfo_info1545);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1545_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1545(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1545,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1546(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1546_, NDR_POINTER_UNIQUE, "Pointer to Info1546 (srvsvc_NetSrvInfo1546)",hf_srvsvc_srvsvc_NetSrvInfo_info1546);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1546_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1546(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1546,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1547(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1547_, NDR_POINTER_UNIQUE, "Pointer to Info1547 (srvsvc_NetSrvInfo1547)",hf_srvsvc_srvsvc_NetSrvInfo_info1547);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1547_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1547(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1547,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1548(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1548_, NDR_POINTER_UNIQUE, "Pointer to Info1548 (srvsvc_NetSrvInfo1548)",hf_srvsvc_srvsvc_NetSrvInfo_info1548);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1548_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1548(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1548,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1549(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1549_, NDR_POINTER_UNIQUE, "Pointer to Info1549 (srvsvc_NetSrvInfo1549)",hf_srvsvc_srvsvc_NetSrvInfo_info1549);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1549_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1549(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1549,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1550(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1550_, NDR_POINTER_UNIQUE, "Pointer to Info1550 (srvsvc_NetSrvInfo1550)",hf_srvsvc_srvsvc_NetSrvInfo_info1550);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1550_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1550(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1550,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1552(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1552_, NDR_POINTER_UNIQUE, "Pointer to Info1552 (srvsvc_NetSrvInfo1552)",hf_srvsvc_srvsvc_NetSrvInfo_info1552);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1552_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1552(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1552,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1553(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1553_, NDR_POINTER_UNIQUE, "Pointer to Info1553 (srvsvc_NetSrvInfo1553)",hf_srvsvc_srvsvc_NetSrvInfo_info1553);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1553_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1553(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1553,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1554(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1554_, NDR_POINTER_UNIQUE, "Pointer to Info1554 (srvsvc_NetSrvInfo1554)",hf_srvsvc_srvsvc_NetSrvInfo_info1554);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1554_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1554(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1554,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1555(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1555_, NDR_POINTER_UNIQUE, "Pointer to Info1555 (srvsvc_NetSrvInfo1555)",hf_srvsvc_srvsvc_NetSrvInfo_info1555);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1555_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1555(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1555,0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1556(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvInfo_info1556_, NDR_POINTER_UNIQUE, "Pointer to Info1556 (srvsvc_NetSrvInfo1556)",hf_srvsvc_srvsvc_NetSrvInfo_info1556);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvInfo_info1556_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetSrvInfo1556(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetSrvInfo_info1556,0);

	return offset;
}

static int
srvsvc_dissect_NetSrvInfo(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint32 level;

	ALIGN_TO_4_BYTES;

	old_offset = offset;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "srvsvc_NetSrvInfo");
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetSrvInfo);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, &level);
	switch(level) {
		case 100:
			offset = srvsvc_dissect_element_NetSrvInfo_info100(tvb, offset, pinfo, tree, drep);
		break;

		case 101:
			offset = srvsvc_dissect_element_NetSrvInfo_info101(tvb, offset, pinfo, tree, drep);
		break;

		case 102:
			offset = srvsvc_dissect_element_NetSrvInfo_info102(tvb, offset, pinfo, tree, drep);
		break;

		case 402:
			offset = srvsvc_dissect_element_NetSrvInfo_info402(tvb, offset, pinfo, tree, drep);
		break;

		case 403:
			offset = srvsvc_dissect_element_NetSrvInfo_info403(tvb, offset, pinfo, tree, drep);
		break;

		case 502:
			offset = srvsvc_dissect_element_NetSrvInfo_info502(tvb, offset, pinfo, tree, drep);
		break;

		case 503:
			offset = srvsvc_dissect_element_NetSrvInfo_info503(tvb, offset, pinfo, tree, drep);
		break;

		case 599:
			offset = srvsvc_dissect_element_NetSrvInfo_info599(tvb, offset, pinfo, tree, drep);
		break;

		case 1005:
			offset = srvsvc_dissect_element_NetSrvInfo_info1005(tvb, offset, pinfo, tree, drep);
		break;

		case 1010:
			offset = srvsvc_dissect_element_NetSrvInfo_info1010(tvb, offset, pinfo, tree, drep);
		break;

		case 1016:
			offset = srvsvc_dissect_element_NetSrvInfo_info1016(tvb, offset, pinfo, tree, drep);
		break;

		case 1017:
			offset = srvsvc_dissect_element_NetSrvInfo_info1017(tvb, offset, pinfo, tree, drep);
		break;

		case 1018:
			offset = srvsvc_dissect_element_NetSrvInfo_info1018(tvb, offset, pinfo, tree, drep);
		break;

		case 1107:
			offset = srvsvc_dissect_element_NetSrvInfo_info1107(tvb, offset, pinfo, tree, drep);
		break;

		case 1501:
			offset = srvsvc_dissect_element_NetSrvInfo_info1501(tvb, offset, pinfo, tree, drep);
		break;

		case 1502:
			offset = srvsvc_dissect_element_NetSrvInfo_info1502(tvb, offset, pinfo, tree, drep);
		break;

		case 1503:
			offset = srvsvc_dissect_element_NetSrvInfo_info1503(tvb, offset, pinfo, tree, drep);
		break;

		case 1506:
			offset = srvsvc_dissect_element_NetSrvInfo_info1506(tvb, offset, pinfo, tree, drep);
		break;

		case 1509:
			offset = srvsvc_dissect_element_NetSrvInfo_info1509(tvb, offset, pinfo, tree, drep);
		break;

		case 1510:
			offset = srvsvc_dissect_element_NetSrvInfo_info1510(tvb, offset, pinfo, tree, drep);
		break;

		case 1511:
			offset = srvsvc_dissect_element_NetSrvInfo_info1511(tvb, offset, pinfo, tree, drep);
		break;

		case 1512:
			offset = srvsvc_dissect_element_NetSrvInfo_info1512(tvb, offset, pinfo, tree, drep);
		break;

		case 1513:
			offset = srvsvc_dissect_element_NetSrvInfo_info1513(tvb, offset, pinfo, tree, drep);
		break;

		case 1514:
			offset = srvsvc_dissect_element_NetSrvInfo_info1514(tvb, offset, pinfo, tree, drep);
		break;

		case 1515:
			offset = srvsvc_dissect_element_NetSrvInfo_info1515(tvb, offset, pinfo, tree, drep);
		break;

		case 1516:
			offset = srvsvc_dissect_element_NetSrvInfo_info1516(tvb, offset, pinfo, tree, drep);
		break;

		case 1518:
			offset = srvsvc_dissect_element_NetSrvInfo_info1518(tvb, offset, pinfo, tree, drep);
		break;

		case 1520:
			offset = srvsvc_dissect_element_NetSrvInfo_info1520(tvb, offset, pinfo, tree, drep);
		break;

		case 1521:
			offset = srvsvc_dissect_element_NetSrvInfo_info1521(tvb, offset, pinfo, tree, drep);
		break;

		case 1522:
			offset = srvsvc_dissect_element_NetSrvInfo_info1522(tvb, offset, pinfo, tree, drep);
		break;

		case 1523:
			offset = srvsvc_dissect_element_NetSrvInfo_info1523(tvb, offset, pinfo, tree, drep);
		break;

		case 1524:
			offset = srvsvc_dissect_element_NetSrvInfo_info1524(tvb, offset, pinfo, tree, drep);
		break;

		case 1525:
			offset = srvsvc_dissect_element_NetSrvInfo_info1525(tvb, offset, pinfo, tree, drep);
		break;

		case 1528:
			offset = srvsvc_dissect_element_NetSrvInfo_info1528(tvb, offset, pinfo, tree, drep);
		break;

		case 1529:
			offset = srvsvc_dissect_element_NetSrvInfo_info1529(tvb, offset, pinfo, tree, drep);
		break;

		case 1530:
			offset = srvsvc_dissect_element_NetSrvInfo_info1530(tvb, offset, pinfo, tree, drep);
		break;

		case 1533:
			offset = srvsvc_dissect_element_NetSrvInfo_info1533(tvb, offset, pinfo, tree, drep);
		break;

		case 1534:
			offset = srvsvc_dissect_element_NetSrvInfo_info1534(tvb, offset, pinfo, tree, drep);
		break;

		case 1535:
			offset = srvsvc_dissect_element_NetSrvInfo_info1535(tvb, offset, pinfo, tree, drep);
		break;

		case 1536:
			offset = srvsvc_dissect_element_NetSrvInfo_info1536(tvb, offset, pinfo, tree, drep);
		break;

		case 1537:
			offset = srvsvc_dissect_element_NetSrvInfo_info1537(tvb, offset, pinfo, tree, drep);
		break;

		case 1538:
			offset = srvsvc_dissect_element_NetSrvInfo_info1538(tvb, offset, pinfo, tree, drep);
		break;

		case 1539:
			offset = srvsvc_dissect_element_NetSrvInfo_info1539(tvb, offset, pinfo, tree, drep);
		break;

		case 1540:
			offset = srvsvc_dissect_element_NetSrvInfo_info1540(tvb, offset, pinfo, tree, drep);
		break;

		case 1541:
			offset = srvsvc_dissect_element_NetSrvInfo_info1541(tvb, offset, pinfo, tree, drep);
		break;

		case 1542:
			offset = srvsvc_dissect_element_NetSrvInfo_info1542(tvb, offset, pinfo, tree, drep);
		break;

		case 1543:
			offset = srvsvc_dissect_element_NetSrvInfo_info1543(tvb, offset, pinfo, tree, drep);
		break;

		case 1544:
			offset = srvsvc_dissect_element_NetSrvInfo_info1544(tvb, offset, pinfo, tree, drep);
		break;

		case 1545:
			offset = srvsvc_dissect_element_NetSrvInfo_info1545(tvb, offset, pinfo, tree, drep);
		break;

		case 1546:
			offset = srvsvc_dissect_element_NetSrvInfo_info1546(tvb, offset, pinfo, tree, drep);
		break;

		case 1547:
			offset = srvsvc_dissect_element_NetSrvInfo_info1547(tvb, offset, pinfo, tree, drep);
		break;

		case 1548:
			offset = srvsvc_dissect_element_NetSrvInfo_info1548(tvb, offset, pinfo, tree, drep);
		break;

		case 1549:
			offset = srvsvc_dissect_element_NetSrvInfo_info1549(tvb, offset, pinfo, tree, drep);
		break;

		case 1550:
			offset = srvsvc_dissect_element_NetSrvInfo_info1550(tvb, offset, pinfo, tree, drep);
		break;

		case 1552:
			offset = srvsvc_dissect_element_NetSrvInfo_info1552(tvb, offset, pinfo, tree, drep);
		break;

		case 1553:
			offset = srvsvc_dissect_element_NetSrvInfo_info1553(tvb, offset, pinfo, tree, drep);
		break;

		case 1554:
			offset = srvsvc_dissect_element_NetSrvInfo_info1554(tvb, offset, pinfo, tree, drep);
		break;

		case 1555:
			offset = srvsvc_dissect_element_NetSrvInfo_info1555(tvb, offset, pinfo, tree, drep);
		break;

		case 1556:
			offset = srvsvc_dissect_element_NetSrvInfo_info1556(tvb, offset, pinfo, tree, drep);
		break;

		default:
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: struct { */
/* IDL: 	[flag(LIBNDR_FLAG_STR_LEN4)] string disk; */
/* IDL: } */

static int
srvsvc_dissect_element_NetDiskInfo0_disk(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{

	return offset;
}

int
srvsvc_dissect_struct_NetDiskInfo0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetDiskInfo0);
	}

	offset = srvsvc_dissect_element_NetDiskInfo0_disk(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [length_is(count)] [size_is(count)] srvsvc_NetDiskInfo0 *disks; */
/* IDL: } */

static int
srvsvc_dissect_element_NetDiskInfo_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetDiskInfo_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetDiskInfo_disks(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetDiskInfo_disks_, NDR_POINTER_UNIQUE, "Pointer to Disks (srvsvc_NetDiskInfo0)",hf_srvsvc_srvsvc_NetDiskInfo_disks);

	return offset;
}

static int
srvsvc_dissect_element_NetDiskInfo_disks_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucvarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetDiskInfo_disks__);

	return offset;
}

static int
srvsvc_dissect_element_NetDiskInfo_disks__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetDiskInfo0(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetDiskInfo_disks,0);

	return offset;
}

int
srvsvc_dissect_struct_NetDiskInfo(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetDiskInfo);
	}

	offset = srvsvc_dissect_element_NetDiskInfo_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetDiskInfo_disks(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 start; */
/* IDL: 	uint32 fopens; */
/* IDL: 	uint32 devopens; */
/* IDL: 	uint32 jobsqueued; */
/* IDL: 	uint32 sopens; */
/* IDL: 	uint32 stimeouts; */
/* IDL: 	uint32 serrorout; */
/* IDL: 	uint32 pwerrors; */
/* IDL: 	uint32 permerrors; */
/* IDL: 	uint32 syserrors; */
/* IDL: 	uint32 bytessent_low; */
/* IDL: 	uint32 bytessent_high; */
/* IDL: 	uint32 bytesrcvd_low; */
/* IDL: 	uint32 bytesrcvd_high; */
/* IDL: 	uint32 avresponse; */
/* IDL: 	uint32 reqbufneed; */
/* IDL: 	uint32 bigbufneed; */
/* IDL: } */

static int
srvsvc_dissect_element_Statistics_start(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_Statistics_start, 0);

	return offset;
}

static int
srvsvc_dissect_element_Statistics_fopens(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_Statistics_fopens, 0);

	return offset;
}

static int
srvsvc_dissect_element_Statistics_devopens(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_Statistics_devopens, 0);

	return offset;
}

static int
srvsvc_dissect_element_Statistics_jobsqueued(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_Statistics_jobsqueued, 0);

	return offset;
}

static int
srvsvc_dissect_element_Statistics_sopens(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_Statistics_sopens, 0);

	return offset;
}

static int
srvsvc_dissect_element_Statistics_stimeouts(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_Statistics_stimeouts, 0);

	return offset;
}

static int
srvsvc_dissect_element_Statistics_serrorout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_Statistics_serrorout, 0);

	return offset;
}

static int
srvsvc_dissect_element_Statistics_pwerrors(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_Statistics_pwerrors, 0);

	return offset;
}

static int
srvsvc_dissect_element_Statistics_permerrors(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_Statistics_permerrors, 0);

	return offset;
}

static int
srvsvc_dissect_element_Statistics_syserrors(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_Statistics_syserrors, 0);

	return offset;
}

static int
srvsvc_dissect_element_Statistics_bytessent_low(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_Statistics_bytessent_low, 0);

	return offset;
}

static int
srvsvc_dissect_element_Statistics_bytessent_high(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_Statistics_bytessent_high, 0);

	return offset;
}

static int
srvsvc_dissect_element_Statistics_bytesrcvd_low(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_Statistics_bytesrcvd_low, 0);

	return offset;
}

static int
srvsvc_dissect_element_Statistics_bytesrcvd_high(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_Statistics_bytesrcvd_high, 0);

	return offset;
}

static int
srvsvc_dissect_element_Statistics_avresponse(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_Statistics_avresponse, 0);

	return offset;
}

static int
srvsvc_dissect_element_Statistics_reqbufneed(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_Statistics_reqbufneed, 0);

	return offset;
}

static int
srvsvc_dissect_element_Statistics_bigbufneed(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_Statistics_bigbufneed, 0);

	return offset;
}

int
srvsvc_dissect_struct_Statistics(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_Statistics);
	}

	offset = srvsvc_dissect_element_Statistics_start(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_Statistics_fopens(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_Statistics_devopens(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_Statistics_jobsqueued(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_Statistics_sopens(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_Statistics_stimeouts(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_Statistics_serrorout(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_Statistics_pwerrors(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_Statistics_permerrors(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_Statistics_syserrors(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_Statistics_bytessent_low(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_Statistics_bytessent_high(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_Statistics_bytesrcvd_low(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_Statistics_bytesrcvd_high(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_Statistics_avresponse(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_Statistics_reqbufneed(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_Statistics_bigbufneed(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 vcs; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *name; */
/* IDL: 	[unique(1)] [size_is(addr_len)] uint8 *addr; */
/* IDL: 	uint32 addr_len; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *net_addr; */
/* IDL: } */

static int
srvsvc_dissect_element_NetTransportInfo0_vcs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportInfo0_vcs, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo0_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportInfo0_name_, NDR_POINTER_UNIQUE, "Pointer to Name (uint16)",hf_srvsvc_srvsvc_NetTransportInfo0_name);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo0_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetTransportInfo0_name, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo0_addr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportInfo0_addr_, NDR_POINTER_UNIQUE, "Pointer to Addr (uint8)",hf_srvsvc_srvsvc_NetTransportInfo0_addr);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo0_addr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportInfo0_addr__);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo0_addr__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportInfo0_addr, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo0_addr_len(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportInfo0_addr_len, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo0_net_addr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportInfo0_net_addr_, NDR_POINTER_UNIQUE, "Pointer to Net Addr (uint16)",hf_srvsvc_srvsvc_NetTransportInfo0_net_addr);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo0_net_addr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetTransportInfo0_net_addr, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetTransportInfo0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetTransportInfo0);
	}

	offset = srvsvc_dissect_element_NetTransportInfo0_vcs(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetTransportInfo0_name(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetTransportInfo0_addr(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetTransportInfo0_addr_len(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetTransportInfo0_net_addr(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] srvsvc_NetTransportInfo0 *array; */
/* IDL: } */

static int
srvsvc_dissect_element_NetTransportCtr0_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportCtr0_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportCtr0_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportCtr0_array_, NDR_POINTER_UNIQUE, "Pointer to Array (srvsvc_NetTransportInfo0)",hf_srvsvc_srvsvc_NetTransportCtr0_array);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportCtr0_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportCtr0_array__);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportCtr0_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetTransportInfo0(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetTransportCtr0_array,0);

	return offset;
}

int
srvsvc_dissect_struct_NetTransportCtr0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetTransportCtr0);
	}

	offset = srvsvc_dissect_element_NetTransportCtr0_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetTransportCtr0_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 vcs; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *name; */
/* IDL: 	[unique(1)] [size_is(addr_len)] uint8 *addr; */
/* IDL: 	uint32 addr_len; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *net_addr; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *domain; */
/* IDL: } */

static int
srvsvc_dissect_element_NetTransportInfo1_vcs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportInfo1_vcs, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo1_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportInfo1_name_, NDR_POINTER_UNIQUE, "Pointer to Name (uint16)",hf_srvsvc_srvsvc_NetTransportInfo1_name);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo1_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetTransportInfo1_name, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo1_addr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportInfo1_addr_, NDR_POINTER_UNIQUE, "Pointer to Addr (uint8)",hf_srvsvc_srvsvc_NetTransportInfo1_addr);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo1_addr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportInfo1_addr__);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo1_addr__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportInfo1_addr, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo1_addr_len(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportInfo1_addr_len, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo1_net_addr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportInfo1_net_addr_, NDR_POINTER_UNIQUE, "Pointer to Net Addr (uint16)",hf_srvsvc_srvsvc_NetTransportInfo1_net_addr);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo1_net_addr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetTransportInfo1_net_addr, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo1_domain(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportInfo1_domain_, NDR_POINTER_UNIQUE, "Pointer to Domain (uint16)",hf_srvsvc_srvsvc_NetTransportInfo1_domain);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo1_domain_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetTransportInfo1_domain, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetTransportInfo1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetTransportInfo1);
	}

	offset = srvsvc_dissect_element_NetTransportInfo1_vcs(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetTransportInfo1_name(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetTransportInfo1_addr(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetTransportInfo1_addr_len(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetTransportInfo1_net_addr(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetTransportInfo1_domain(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] srvsvc_NetTransportInfo1 *array; */
/* IDL: } */

static int
srvsvc_dissect_element_NetTransportCtr1_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportCtr1_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportCtr1_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportCtr1_array_, NDR_POINTER_UNIQUE, "Pointer to Array (srvsvc_NetTransportInfo1)",hf_srvsvc_srvsvc_NetTransportCtr1_array);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportCtr1_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportCtr1_array__);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportCtr1_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetTransportInfo1(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetTransportCtr1_array,0);

	return offset;
}

int
srvsvc_dissect_struct_NetTransportCtr1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetTransportCtr1);
	}

	offset = srvsvc_dissect_element_NetTransportCtr1_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetTransportCtr1_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: bitmap { */
/* IDL: 	SVTI2_REMAP_PIPE_NAMES =  0x00000001 , */
/* IDL: } */

int
srvsvc_dissect_bitmap_TransportFlags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	guint32 flags;
	ALIGN_TO_4_BYTES;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 4, TRUE);
		tree = proto_item_add_subtree(item,ett_srvsvc_srvsvc_TransportFlags);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep, -1, &flags);
	proto_item_append_text(item, ": ");

	if (!flags)
		proto_item_append_text(item, "(No values set)");

	proto_tree_add_boolean(tree, hf_srvsvc_srvsvc_TransportFlags_SVTI2_REMAP_PIPE_NAMES, tvb, offset-4, 4, flags);
	if (flags&( 0x00000001 )){
		proto_item_append_text(item, "SVTI2_REMAP_PIPE_NAMES");
		if (flags & (~( 0x00000001 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x00000001 ));

	if (flags) {
		proto_item_append_text(item, "Unknown bitmap value 0x%x", flags);
	}

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 vcs; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *name; */
/* IDL: 	[unique(1)] [size_is(addr_len)] uint8 *addr; */
/* IDL: 	uint32 addr_len; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *net_addr; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *domain; */
/* IDL: 	srvsvc_TransportFlags transport_flags; */
/* IDL: } */

static int
srvsvc_dissect_element_NetTransportInfo2_vcs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportInfo2_vcs, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo2_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportInfo2_name_, NDR_POINTER_UNIQUE, "Pointer to Name (uint16)",hf_srvsvc_srvsvc_NetTransportInfo2_name);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo2_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetTransportInfo2_name, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo2_addr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportInfo2_addr_, NDR_POINTER_UNIQUE, "Pointer to Addr (uint8)",hf_srvsvc_srvsvc_NetTransportInfo2_addr);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo2_addr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportInfo2_addr__);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo2_addr__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportInfo2_addr, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo2_addr_len(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportInfo2_addr_len, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo2_net_addr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportInfo2_net_addr_, NDR_POINTER_UNIQUE, "Pointer to Net Addr (uint16)",hf_srvsvc_srvsvc_NetTransportInfo2_net_addr);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo2_net_addr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetTransportInfo2_net_addr, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo2_domain(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportInfo2_domain_, NDR_POINTER_UNIQUE, "Pointer to Domain (uint16)",hf_srvsvc_srvsvc_NetTransportInfo2_domain);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo2_domain_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetTransportInfo2_domain, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo2_transport_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_bitmap_TransportFlags(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportInfo2_transport_flags, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetTransportInfo2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetTransportInfo2);
	}

	offset = srvsvc_dissect_element_NetTransportInfo2_vcs(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetTransportInfo2_name(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetTransportInfo2_addr(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetTransportInfo2_addr_len(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetTransportInfo2_net_addr(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetTransportInfo2_domain(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetTransportInfo2_transport_flags(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] srvsvc_NetTransportInfo2 *array; */
/* IDL: } */

static int
srvsvc_dissect_element_NetTransportCtr2_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportCtr2_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportCtr2_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportCtr2_array_, NDR_POINTER_UNIQUE, "Pointer to Array (srvsvc_NetTransportInfo2)",hf_srvsvc_srvsvc_NetTransportCtr2_array);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportCtr2_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportCtr2_array__);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportCtr2_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetTransportInfo2(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetTransportCtr2_array,0);

	return offset;
}

int
srvsvc_dissect_struct_NetTransportCtr2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetTransportCtr2);
	}

	offset = srvsvc_dissect_element_NetTransportCtr2_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetTransportCtr2_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 vcs; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *name; */
/* IDL: 	[unique(1)] [size_is(addr_len)] uint8 *addr; */
/* IDL: 	uint32 addr_len; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *net_addr; */
/* IDL: 	[unique(1)] [charset(UTF16)] uint16 *domain; */
/* IDL: 	srvsvc_TransportFlags transport_flags; */
/* IDL: 	uint32 password_len; */
/* IDL: 	uint8 password[256]; */
/* IDL: } */

static int
srvsvc_dissect_element_NetTransportInfo3_vcs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportInfo3_vcs, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo3_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportInfo3_name_, NDR_POINTER_UNIQUE, "Pointer to Name (uint16)",hf_srvsvc_srvsvc_NetTransportInfo3_name);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo3_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetTransportInfo3_name, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo3_addr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportInfo3_addr_, NDR_POINTER_UNIQUE, "Pointer to Addr (uint8)",hf_srvsvc_srvsvc_NetTransportInfo3_addr);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo3_addr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportInfo3_addr__);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo3_addr__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportInfo3_addr, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo3_addr_len(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportInfo3_addr_len, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo3_net_addr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportInfo3_net_addr_, NDR_POINTER_UNIQUE, "Pointer to Net Addr (uint16)",hf_srvsvc_srvsvc_NetTransportInfo3_net_addr);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo3_net_addr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetTransportInfo3_net_addr, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo3_domain(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportInfo3_domain_, NDR_POINTER_UNIQUE, "Pointer to Domain (uint16)",hf_srvsvc_srvsvc_NetTransportInfo3_domain);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo3_domain_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetTransportInfo3_domain, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo3_transport_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_bitmap_TransportFlags(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportInfo3_transport_flags, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo3_password_len(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportInfo3_password_len, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo3_password(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	int i;
	for (i = 0; i < 256; i++)
		offset = srvsvc_dissect_element_NetTransportInfo3_password_(tvb, offset, pinfo, tree, drep);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo3_password_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportInfo3_password, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetTransportInfo3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetTransportInfo3);
	}

	offset = srvsvc_dissect_element_NetTransportInfo3_vcs(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetTransportInfo3_name(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetTransportInfo3_addr(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetTransportInfo3_addr_len(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetTransportInfo3_net_addr(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetTransportInfo3_domain(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetTransportInfo3_transport_flags(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetTransportInfo3_password_len(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetTransportInfo3_password(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 count; */
/* IDL: 	[unique(1)] [size_is(count)] srvsvc_NetTransportInfo3 *array; */
/* IDL: } */

static int
srvsvc_dissect_element_NetTransportCtr3_count(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportCtr3_count, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportCtr3_array(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportCtr3_array_, NDR_POINTER_UNIQUE, "Pointer to Array (srvsvc_NetTransportInfo3)",hf_srvsvc_srvsvc_NetTransportCtr3_array);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportCtr3_array_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportCtr3_array__);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportCtr3_array__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetTransportInfo3(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetTransportCtr3_array,0);

	return offset;
}

int
srvsvc_dissect_struct_NetTransportCtr3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetTransportCtr3);
	}

	offset = srvsvc_dissect_element_NetTransportCtr3_count(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetTransportCtr3_array(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: union { */
/* IDL: [case(0)] [unique(1)] [case(0)] srvsvc_NetTransportCtr0 *ctr0; */
/* IDL: [case(1)] [unique(1)] [case(1)] srvsvc_NetTransportCtr1 *ctr1; */
/* IDL: [case(2)] [unique(1)] [case(2)] srvsvc_NetTransportCtr2 *ctr2; */
/* IDL: [case(3)] [unique(1)] [case(3)] srvsvc_NetTransportCtr3 *ctr3; */
/* IDL: [default] ; */
/* IDL: } */

static int
srvsvc_dissect_element_NetTransportCtr_ctr0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportCtr_ctr0_, NDR_POINTER_UNIQUE, "Pointer to Ctr0 (srvsvc_NetTransportCtr0)",hf_srvsvc_srvsvc_NetTransportCtr_ctr0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportCtr_ctr0_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetTransportCtr0(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetTransportCtr_ctr0,0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportCtr_ctr1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportCtr_ctr1_, NDR_POINTER_UNIQUE, "Pointer to Ctr1 (srvsvc_NetTransportCtr1)",hf_srvsvc_srvsvc_NetTransportCtr_ctr1);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportCtr_ctr1_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetTransportCtr1(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetTransportCtr_ctr1,0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportCtr_ctr2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportCtr_ctr2_, NDR_POINTER_UNIQUE, "Pointer to Ctr2 (srvsvc_NetTransportCtr2)",hf_srvsvc_srvsvc_NetTransportCtr_ctr2);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportCtr_ctr2_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetTransportCtr2(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetTransportCtr_ctr2,0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportCtr_ctr3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportCtr_ctr3_, NDR_POINTER_UNIQUE, "Pointer to Ctr3 (srvsvc_NetTransportCtr3)",hf_srvsvc_srvsvc_NetTransportCtr_ctr3);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportCtr_ctr3_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetTransportCtr3(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetTransportCtr_ctr3,0);

	return offset;
}

static int
srvsvc_dissect_NetTransportCtr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint32 level;

	ALIGN_TO_4_BYTES;

	old_offset = offset;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "srvsvc_NetTransportCtr");
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetTransportCtr);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, &level);
	switch(level) {
		case 0:
			offset = srvsvc_dissect_element_NetTransportCtr_ctr0(tvb, offset, pinfo, tree, drep);
		break;

		case 1:
			offset = srvsvc_dissect_element_NetTransportCtr_ctr1(tvb, offset, pinfo, tree, drep);
		break;

		case 2:
			offset = srvsvc_dissect_element_NetTransportCtr_ctr2(tvb, offset, pinfo, tree, drep);
		break;

		case 3:
			offset = srvsvc_dissect_element_NetTransportCtr_ctr3(tvb, offset, pinfo, tree, drep);
		break;

		default:
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}

/* IDL: struct { */
/* IDL: 	uint32 elapsed; */
/* IDL: 	uint32 msecs; */
/* IDL: 	uint32 hours; */
/* IDL: 	uint32 mins; */
/* IDL: 	uint32 secs; */
/* IDL: 	uint32 hunds; */
/* IDL: 	int32 timezone; */
/* IDL: 	uint32 tinterval; */
/* IDL: 	uint32 day; */
/* IDL: 	uint32 month; */
/* IDL: 	uint32 year; */
/* IDL: 	uint32 weekday; */
/* IDL: } */

static int
srvsvc_dissect_element_NetRemoteTODInfo_elapsed(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetRemoteTODInfo_elapsed, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetRemoteTODInfo_msecs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetRemoteTODInfo_msecs, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetRemoteTODInfo_hours(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetRemoteTODInfo_hours, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetRemoteTODInfo_mins(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetRemoteTODInfo_mins, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetRemoteTODInfo_secs(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetRemoteTODInfo_secs, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetRemoteTODInfo_hunds(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetRemoteTODInfo_hunds, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetRemoteTODInfo_timezone(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetRemoteTODInfo_timezone, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetRemoteTODInfo_tinterval(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetRemoteTODInfo_tinterval, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetRemoteTODInfo_day(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetRemoteTODInfo_day, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetRemoteTODInfo_month(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetRemoteTODInfo_month, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetRemoteTODInfo_year(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetRemoteTODInfo_year, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetRemoteTODInfo_weekday(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetRemoteTODInfo_weekday, 0);

	return offset;
}

int
srvsvc_dissect_struct_NetRemoteTODInfo(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetRemoteTODInfo);
	}

	offset = srvsvc_dissect_element_NetRemoteTODInfo_elapsed(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetRemoteTODInfo_msecs(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetRemoteTODInfo_hours(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetRemoteTODInfo_mins(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetRemoteTODInfo_secs(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetRemoteTODInfo_hunds(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetRemoteTODInfo_timezone(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetRemoteTODInfo_tinterval(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetRemoteTODInfo_day(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetRemoteTODInfo_month(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetRemoteTODInfo_year(tvb, offset, pinfo, tree, drep);

	offset = srvsvc_dissect_element_NetRemoteTODInfo_weekday(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: [switch_type(uint32)] union { */
/* IDL: [case(0)] [case(0)] srvsvc_NetTransportInfo0 info0; */
/* IDL: [case(1)] [case(1)] srvsvc_NetTransportInfo1 info1; */
/* IDL: [case(2)] [case(2)] srvsvc_NetTransportInfo2 info2; */
/* IDL: [case(3)] [case(3)] srvsvc_NetTransportInfo3 info3; */
/* IDL: } */

static int
srvsvc_dissect_element_NetTransportInfo_info0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetTransportInfo0(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetTransportInfo_info0,0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo_info1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetTransportInfo1(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetTransportInfo_info1,0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo_info2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetTransportInfo2(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetTransportInfo_info2,0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportInfo_info3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetTransportInfo3(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetTransportInfo_info3,0);

	return offset;
}

static int
srvsvc_dissect_NetTransportInfo(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;
	guint32 level;

	ALIGN_TO_4_BYTES;

	old_offset = offset;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "srvsvc_NetTransportInfo");
		tree = proto_item_add_subtree(item, ett_srvsvc_srvsvc_NetTransportInfo);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, &level);
	switch(level) {
		case 0:
			offset = srvsvc_dissect_element_NetTransportInfo_info0(tvb, offset, pinfo, tree, drep);
		break;

		case 1:
			offset = srvsvc_dissect_element_NetTransportInfo_info1(tvb, offset, pinfo, tree, drep);
		break;

		case 2:
			offset = srvsvc_dissect_element_NetTransportInfo_info2(tvb, offset, pinfo, tree, drep);
		break;

		case 3:
			offset = srvsvc_dissect_element_NetTransportInfo_info3(tvb, offset, pinfo, tree, drep);
		break;
	}
	proto_item_set_len(item, offset-old_offset);

	return offset;
}
static int
srvsvc_dissect_element_NetCharDevEnum_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevEnum_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetCharDevEnum_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevEnum_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetCharDevEnum_server_unc, 1|PIDL_SET_COL_INFO);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevEnum_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevEnum_level_, NDR_POINTER_REF, "Pointer to Level (uint32)",hf_srvsvc_srvsvc_NetCharDevEnum_level);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevEnum_level_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetCharDevEnum_level, PIDL_SET_COL_INFO);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevEnum_ctr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevEnum_ctr_, NDR_POINTER_REF, "Pointer to Ctr (srvsvc_NetCharDevCtr)",hf_srvsvc_srvsvc_NetCharDevEnum_ctr);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevEnum_ctr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_NetCharDevCtr(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetCharDevEnum_ctr, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevEnum_max_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetCharDevEnum_max_buffer, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevEnum_totalentries(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevEnum_totalentries_, NDR_POINTER_REF, "Pointer to Totalentries (uint32)",hf_srvsvc_srvsvc_NetCharDevEnum_totalentries);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevEnum_totalentries_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetCharDevEnum_totalentries, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevEnum_resume_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevEnum_resume_handle_, NDR_POINTER_UNIQUE, "Pointer to Resume Handle (uint32)",hf_srvsvc_srvsvc_NetCharDevEnum_resume_handle);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevEnum_resume_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetCharDevEnum_resume_handle, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetCharDevEnum( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [out] [in] [ref] uint32 *level, */
/* IDL: [out] [in] [ref] [switch_is(level)] srvsvc_NetCharDevCtr *ctr, */
/* IDL: [in] uint32 max_buffer, */
/* IDL: [out] [ref] uint32 *totalentries, */
/* IDL: [unique(1)] [out] [in] uint32 *resume_handle */
/* IDL: ); */

static int
srvsvc_dissect_NetCharDevEnum_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetCharDevEnum";
	offset = srvsvc_dissect_element_NetCharDevEnum_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = srvsvc_dissect_element_NetCharDevEnum_ctr(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = srvsvc_dissect_element_NetCharDevEnum_totalentries(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = srvsvc_dissect_element_NetCharDevEnum_resume_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetCharDevEnum_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetCharDevEnum";
	offset = srvsvc_dissect_element_NetCharDevEnum_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetCharDevEnum_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetCharDevEnum_ctr(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetCharDevEnum_max_buffer(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetCharDevEnum_resume_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetCharDevGetInfo_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevGetInfo_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetCharDevGetInfo_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevGetInfo_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetCharDevGetInfo_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevGetInfo_device_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetCharDevGetInfo_device_name, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevGetInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetCharDevGetInfo_level, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevGetInfo_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevGetInfo_info_, NDR_POINTER_REF, "Pointer to Info (srvsvc_NetCharDevInfo)",hf_srvsvc_srvsvc_NetCharDevGetInfo_info);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevGetInfo_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_NetCharDevInfo(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetCharDevGetInfo_info, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetCharDevGetInfo( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [in] [charset(UTF16)] uint16 device_name[*], */
/* IDL: [in] uint32 level, */
/* IDL: [out] [ref] [switch_is(level)] srvsvc_NetCharDevInfo *info */
/* IDL: ); */

static int
srvsvc_dissect_NetCharDevGetInfo_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetCharDevGetInfo";
	offset = srvsvc_dissect_element_NetCharDevGetInfo_info(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetCharDevGetInfo_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetCharDevGetInfo";
	offset = srvsvc_dissect_element_NetCharDevGetInfo_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetCharDevGetInfo_device_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetCharDevGetInfo_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetCharDevControl_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevControl_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetCharDevControl_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevControl_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetCharDevControl_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevControl_device_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetCharDevControl_device_name, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevControl_opcode(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetCharDevControl_opcode, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetCharDevControl( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [in] [charset(UTF16)] uint16 device_name[*], */
/* IDL: [in] uint32 opcode */
/* IDL: ); */

static int
srvsvc_dissect_NetCharDevControl_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetCharDevControl";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetCharDevControl_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetCharDevControl";
	offset = srvsvc_dissect_element_NetCharDevControl_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetCharDevControl_device_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetCharDevControl_opcode(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQEnum_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevQEnum_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetCharDevQEnum_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQEnum_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetCharDevQEnum_server_unc, 1|PIDL_SET_COL_INFO);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQEnum_user(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevQEnum_user_, NDR_POINTER_UNIQUE, "Pointer to User (uint16)",hf_srvsvc_srvsvc_NetCharDevQEnum_user);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQEnum_user_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetCharDevQEnum_user, 1|PIDL_SET_COL_INFO);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQEnum_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevQEnum_level_, NDR_POINTER_REF, "Pointer to Level (uint32)",hf_srvsvc_srvsvc_NetCharDevQEnum_level);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQEnum_level_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetCharDevQEnum_level, PIDL_SET_COL_INFO);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQEnum_ctr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevQEnum_ctr_, NDR_POINTER_REF, "Pointer to Ctr (srvsvc_NetCharDevQCtr)",hf_srvsvc_srvsvc_NetCharDevQEnum_ctr);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQEnum_ctr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_NetCharDevQCtr(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetCharDevQEnum_ctr, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQEnum_max_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetCharDevQEnum_max_buffer, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQEnum_totalentries(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevQEnum_totalentries_, NDR_POINTER_REF, "Pointer to Totalentries (uint32)",hf_srvsvc_srvsvc_NetCharDevQEnum_totalentries);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQEnum_totalentries_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetCharDevQEnum_totalentries, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQEnum_resume_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevQEnum_resume_handle_, NDR_POINTER_UNIQUE, "Pointer to Resume Handle (uint32)",hf_srvsvc_srvsvc_NetCharDevQEnum_resume_handle);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQEnum_resume_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetCharDevQEnum_resume_handle, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetCharDevQEnum( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *user, */
/* IDL: [out] [in] [ref] uint32 *level, */
/* IDL: [out] [in] [ref] [switch_is(level)] srvsvc_NetCharDevQCtr *ctr, */
/* IDL: [in] uint32 max_buffer, */
/* IDL: [out] [ref] uint32 *totalentries, */
/* IDL: [unique(1)] [out] [in] uint32 *resume_handle */
/* IDL: ); */

static int
srvsvc_dissect_NetCharDevQEnum_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetCharDevQEnum";
	offset = srvsvc_dissect_element_NetCharDevQEnum_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = srvsvc_dissect_element_NetCharDevQEnum_ctr(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = srvsvc_dissect_element_NetCharDevQEnum_totalentries(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = srvsvc_dissect_element_NetCharDevQEnum_resume_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetCharDevQEnum_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetCharDevQEnum";
	offset = srvsvc_dissect_element_NetCharDevQEnum_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetCharDevQEnum_user(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetCharDevQEnum_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetCharDevQEnum_ctr(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetCharDevQEnum_max_buffer(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetCharDevQEnum_resume_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQGetInfo_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevQGetInfo_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetCharDevQGetInfo_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQGetInfo_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetCharDevQGetInfo_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQGetInfo_queue_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetCharDevQGetInfo_queue_name, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQGetInfo_user(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetCharDevQGetInfo_user, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQGetInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetCharDevQGetInfo_level, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQGetInfo_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevQGetInfo_info_, NDR_POINTER_REF, "Pointer to Info (srvsvc_NetCharDevQInfo)",hf_srvsvc_srvsvc_NetCharDevQGetInfo_info);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQGetInfo_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_NetCharDevQInfo(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetCharDevQGetInfo_info, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetCharDevQGetInfo( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [in] [charset(UTF16)] uint16 queue_name[*], */
/* IDL: [in] [charset(UTF16)] uint16 user[*], */
/* IDL: [in] uint32 level, */
/* IDL: [out] [ref] [switch_is(level)] srvsvc_NetCharDevQInfo *info */
/* IDL: ); */

static int
srvsvc_dissect_NetCharDevQGetInfo_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetCharDevQGetInfo";
	offset = srvsvc_dissect_element_NetCharDevQGetInfo_info(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetCharDevQGetInfo_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetCharDevQGetInfo";
	offset = srvsvc_dissect_element_NetCharDevQGetInfo_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetCharDevQGetInfo_queue_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetCharDevQGetInfo_user(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetCharDevQGetInfo_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQSetInfo_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevQSetInfo_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetCharDevQSetInfo_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQSetInfo_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetCharDevQSetInfo_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQSetInfo_queue_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetCharDevQSetInfo_queue_name, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQSetInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetCharDevQSetInfo_level, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQSetInfo_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_NetCharDevQInfo(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetCharDevQSetInfo_info, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQSetInfo_parm_error(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevQSetInfo_parm_error_, NDR_POINTER_UNIQUE, "Pointer to Parm Error (uint32)",hf_srvsvc_srvsvc_NetCharDevQSetInfo_parm_error);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQSetInfo_parm_error_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetCharDevQSetInfo_parm_error, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetCharDevQSetInfo( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [in] [charset(UTF16)] uint16 queue_name[*], */
/* IDL: [in] uint32 level, */
/* IDL: [in] [switch_is(level)] srvsvc_NetCharDevQInfo info, */
/* IDL: [unique(1)] [out] [in] uint32 *parm_error */
/* IDL: ); */

static int
srvsvc_dissect_NetCharDevQSetInfo_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetCharDevQSetInfo";
	offset = srvsvc_dissect_element_NetCharDevQSetInfo_parm_error(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetCharDevQSetInfo_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetCharDevQSetInfo";
	offset = srvsvc_dissect_element_NetCharDevQSetInfo_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetCharDevQSetInfo_queue_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetCharDevQSetInfo_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetCharDevQSetInfo_info(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetCharDevQSetInfo_parm_error(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQPurge_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevQPurge_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetCharDevQPurge_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQPurge_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetCharDevQPurge_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQPurge_queue_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetCharDevQPurge_queue_name, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetCharDevQPurge( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [in] [charset(UTF16)] uint16 queue_name[*] */
/* IDL: ); */

static int
srvsvc_dissect_NetCharDevQPurge_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetCharDevQPurge";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetCharDevQPurge_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetCharDevQPurge";
	offset = srvsvc_dissect_element_NetCharDevQPurge_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetCharDevQPurge_queue_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQPurgeSelf_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetCharDevQPurgeSelf_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetCharDevQPurgeSelf_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQPurgeSelf_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetCharDevQPurgeSelf_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQPurgeSelf_queue_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetCharDevQPurgeSelf_queue_name, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetCharDevQPurgeSelf_computer_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetCharDevQPurgeSelf_computer_name, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetCharDevQPurgeSelf( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [in] [charset(UTF16)] uint16 queue_name[*], */
/* IDL: [in] [charset(UTF16)] uint16 computer_name[*] */
/* IDL: ); */

static int
srvsvc_dissect_NetCharDevQPurgeSelf_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetCharDevQPurgeSelf";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetCharDevQPurgeSelf_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetCharDevQPurgeSelf";
	offset = srvsvc_dissect_element_NetCharDevQPurgeSelf_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetCharDevQPurgeSelf_queue_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetCharDevQPurgeSelf_computer_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetConnEnum_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetConnEnum_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetConnEnum_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetConnEnum_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetConnEnum_server_unc, 1|PIDL_SET_COL_INFO);

	return offset;
}

static int
srvsvc_dissect_element_NetConnEnum_path(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetConnEnum_path_, NDR_POINTER_UNIQUE, "Pointer to Path (uint16)",hf_srvsvc_srvsvc_NetConnEnum_path);

	return offset;
}

static int
srvsvc_dissect_element_NetConnEnum_path_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetConnEnum_path, 1|PIDL_SET_COL_INFO);

	return offset;
}

static int
srvsvc_dissect_element_NetConnEnum_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetConnEnum_level_, NDR_POINTER_REF, "Pointer to Level (uint32)",hf_srvsvc_srvsvc_NetConnEnum_level);

	return offset;
}

static int
srvsvc_dissect_element_NetConnEnum_level_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetConnEnum_level, PIDL_SET_COL_INFO);

	return offset;
}

static int
srvsvc_dissect_element_NetConnEnum_ctr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetConnEnum_ctr_, NDR_POINTER_REF, "Pointer to Ctr (srvsvc_NetConnCtr)",hf_srvsvc_srvsvc_NetConnEnum_ctr);

	return offset;
}

static int
srvsvc_dissect_element_NetConnEnum_ctr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_NetConnCtr(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetConnEnum_ctr, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetConnEnum_max_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetConnEnum_max_buffer, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetConnEnum_totalentries(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetConnEnum_totalentries_, NDR_POINTER_REF, "Pointer to Totalentries (uint32)",hf_srvsvc_srvsvc_NetConnEnum_totalentries);

	return offset;
}

static int
srvsvc_dissect_element_NetConnEnum_totalentries_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetConnEnum_totalentries, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetConnEnum_resume_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetConnEnum_resume_handle_, NDR_POINTER_UNIQUE, "Pointer to Resume Handle (uint32)",hf_srvsvc_srvsvc_NetConnEnum_resume_handle);

	return offset;
}

static int
srvsvc_dissect_element_NetConnEnum_resume_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetConnEnum_resume_handle, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetConnEnum( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *path, */
/* IDL: [out] [in] [ref] uint32 *level, */
/* IDL: [out] [in] [ref] [switch_is(level)] srvsvc_NetConnCtr *ctr, */
/* IDL: [in] uint32 max_buffer, */
/* IDL: [out] [ref] uint32 *totalentries, */
/* IDL: [unique(1)] [out] [in] uint32 *resume_handle */
/* IDL: ); */

static int
srvsvc_dissect_NetConnEnum_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetConnEnum";
	offset = srvsvc_dissect_element_NetConnEnum_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = srvsvc_dissect_element_NetConnEnum_ctr(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = srvsvc_dissect_element_NetConnEnum_totalentries(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = srvsvc_dissect_element_NetConnEnum_resume_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetConnEnum_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetConnEnum";
	offset = srvsvc_dissect_element_NetConnEnum_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetConnEnum_path(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetConnEnum_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetConnEnum_ctr(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetConnEnum_max_buffer(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetConnEnum_resume_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetFileEnum_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetFileEnum_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetFileEnum_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetFileEnum_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetFileEnum_server_unc, 1|PIDL_SET_COL_INFO);

	return offset;
}

static int
srvsvc_dissect_element_NetFileEnum_path(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetFileEnum_path_, NDR_POINTER_UNIQUE, "Pointer to Path (uint16)",hf_srvsvc_srvsvc_NetFileEnum_path);

	return offset;
}

static int
srvsvc_dissect_element_NetFileEnum_path_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetFileEnum_path, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetFileEnum_user(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetFileEnum_user_, NDR_POINTER_UNIQUE, "Pointer to User (uint16)",hf_srvsvc_srvsvc_NetFileEnum_user);

	return offset;
}

static int
srvsvc_dissect_element_NetFileEnum_user_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetFileEnum_user, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetFileEnum_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetFileEnum_level_, NDR_POINTER_REF, "Pointer to Level (uint32)",hf_srvsvc_srvsvc_NetFileEnum_level);

	return offset;
}

static int
srvsvc_dissect_element_NetFileEnum_level_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetFileEnum_level, PIDL_SET_COL_INFO);

	return offset;
}

static int
srvsvc_dissect_element_NetFileEnum_ctr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetFileEnum_ctr_, NDR_POINTER_REF, "Pointer to Ctr (srvsvc_NetFileCtr)",hf_srvsvc_srvsvc_NetFileEnum_ctr);

	return offset;
}

static int
srvsvc_dissect_element_NetFileEnum_ctr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_NetFileCtr(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetFileEnum_ctr, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetFileEnum_max_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetFileEnum_max_buffer, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetFileEnum_totalentries(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetFileEnum_totalentries_, NDR_POINTER_REF, "Pointer to Totalentries (uint32)",hf_srvsvc_srvsvc_NetFileEnum_totalentries);

	return offset;
}

static int
srvsvc_dissect_element_NetFileEnum_totalentries_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetFileEnum_totalentries, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetFileEnum_resume_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetFileEnum_resume_handle_, NDR_POINTER_UNIQUE, "Pointer to Resume Handle (uint32)",hf_srvsvc_srvsvc_NetFileEnum_resume_handle);

	return offset;
}

static int
srvsvc_dissect_element_NetFileEnum_resume_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetFileEnum_resume_handle, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetFileEnum( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *path, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *user, */
/* IDL: [out] [in] [ref] uint32 *level, */
/* IDL: [out] [in] [ref] [switch_is(level)] srvsvc_NetFileCtr *ctr, */
/* IDL: [in] uint32 max_buffer, */
/* IDL: [out] [ref] uint32 *totalentries, */
/* IDL: [unique(1)] [out] [in] uint32 *resume_handle */
/* IDL: ); */

static int
srvsvc_dissect_NetFileEnum_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetFileEnum";
	offset = srvsvc_dissect_element_NetFileEnum_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = srvsvc_dissect_element_NetFileEnum_ctr(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = srvsvc_dissect_element_NetFileEnum_totalentries(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = srvsvc_dissect_element_NetFileEnum_resume_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetFileEnum_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetFileEnum";
	offset = srvsvc_dissect_element_NetFileEnum_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetFileEnum_path(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetFileEnum_user(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetFileEnum_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetFileEnum_ctr(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetFileEnum_max_buffer(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetFileEnum_resume_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetFileGetInfo_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetFileGetInfo_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetFileGetInfo_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetFileGetInfo_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetFileGetInfo_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetFileGetInfo_fid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetFileGetInfo_fid, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetFileGetInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetFileGetInfo_level, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetFileGetInfo_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetFileGetInfo_info_, NDR_POINTER_REF, "Pointer to Info (srvsvc_NetFileInfo)",hf_srvsvc_srvsvc_NetFileGetInfo_info);

	return offset;
}

static int
srvsvc_dissect_element_NetFileGetInfo_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_NetFileInfo(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetFileGetInfo_info, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetFileGetInfo( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [in] uint32 fid, */
/* IDL: [in] uint32 level, */
/* IDL: [out] [ref] [switch_is(level)] srvsvc_NetFileInfo *info */
/* IDL: ); */

static int
srvsvc_dissect_NetFileGetInfo_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetFileGetInfo";
	offset = srvsvc_dissect_element_NetFileGetInfo_info(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetFileGetInfo_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetFileGetInfo";
	offset = srvsvc_dissect_element_NetFileGetInfo_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetFileGetInfo_fid(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetFileGetInfo_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetFileClose_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetFileClose_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetFileClose_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetFileClose_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetFileClose_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetFileClose_fid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetFileClose_fid, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetFileClose( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [in] uint32 fid */
/* IDL: ); */

static int
srvsvc_dissect_NetFileClose_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetFileClose";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetFileClose_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetFileClose";
	offset = srvsvc_dissect_element_NetFileClose_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetFileClose_fid(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetSessEnum_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessEnum_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetSessEnum_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetSessEnum_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSessEnum_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessEnum_client(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessEnum_client_, NDR_POINTER_UNIQUE, "Pointer to Client (uint16)",hf_srvsvc_srvsvc_NetSessEnum_client);

	return offset;
}

static int
srvsvc_dissect_element_NetSessEnum_client_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSessEnum_client, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessEnum_user(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessEnum_user_, NDR_POINTER_UNIQUE, "Pointer to User (uint16)",hf_srvsvc_srvsvc_NetSessEnum_user);

	return offset;
}

static int
srvsvc_dissect_element_NetSessEnum_user_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSessEnum_user, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessEnum_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessEnum_level_, NDR_POINTER_REF, "Pointer to Level (uint32)",hf_srvsvc_srvsvc_NetSessEnum_level);

	return offset;
}

static int
srvsvc_dissect_element_NetSessEnum_level_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSessEnum_level, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessEnum_ctr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessEnum_ctr_, NDR_POINTER_REF, "Pointer to Ctr (srvsvc_NetSessCtr)",hf_srvsvc_srvsvc_NetSessEnum_ctr);

	return offset;
}

static int
srvsvc_dissect_element_NetSessEnum_ctr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_NetSessCtr(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSessEnum_ctr, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessEnum_max_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSessEnum_max_buffer, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessEnum_totalentries(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessEnum_totalentries_, NDR_POINTER_REF, "Pointer to Totalentries (uint32)",hf_srvsvc_srvsvc_NetSessEnum_totalentries);

	return offset;
}

static int
srvsvc_dissect_element_NetSessEnum_totalentries_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSessEnum_totalentries, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessEnum_resume_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessEnum_resume_handle_, NDR_POINTER_UNIQUE, "Pointer to Resume Handle (uint32)",hf_srvsvc_srvsvc_NetSessEnum_resume_handle);

	return offset;
}

static int
srvsvc_dissect_element_NetSessEnum_resume_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSessEnum_resume_handle, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetSessEnum( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *client, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *user, */
/* IDL: [out] [in] [ref] uint32 *level, */
/* IDL: [out] [in] [ref] [switch_is(level)] srvsvc_NetSessCtr *ctr, */
/* IDL: [in] uint32 max_buffer, */
/* IDL: [out] [ref] uint32 *totalentries, */
/* IDL: [unique(1)] [out] [in] uint32 *resume_handle */
/* IDL: ); */

static int
srvsvc_dissect_NetSessEnum_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetSessEnum";
	offset = srvsvc_dissect_element_NetSessEnum_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = srvsvc_dissect_element_NetSessEnum_ctr(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = srvsvc_dissect_element_NetSessEnum_totalentries(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = srvsvc_dissect_element_NetSessEnum_resume_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetSessEnum_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetSessEnum";
	offset = srvsvc_dissect_element_NetSessEnum_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetSessEnum_client(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetSessEnum_user(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetSessEnum_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetSessEnum_ctr(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetSessEnum_max_buffer(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetSessEnum_resume_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetSessDel_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessDel_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetSessDel_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetSessDel_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSessDel_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessDel_client(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessDel_client_, NDR_POINTER_UNIQUE, "Pointer to Client (uint16)",hf_srvsvc_srvsvc_NetSessDel_client);

	return offset;
}

static int
srvsvc_dissect_element_NetSessDel_client_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSessDel_client, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSessDel_user(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSessDel_user_, NDR_POINTER_UNIQUE, "Pointer to User (uint16)",hf_srvsvc_srvsvc_NetSessDel_user);

	return offset;
}

static int
srvsvc_dissect_element_NetSessDel_user_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSessDel_user, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetSessDel( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *client, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *user */
/* IDL: ); */

static int
srvsvc_dissect_NetSessDel_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetSessDel";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetSessDel_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetSessDel";
	offset = srvsvc_dissect_element_NetSessDel_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetSessDel_client(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetSessDel_user(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetShareAdd_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareAdd_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetShareAdd_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetShareAdd_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareAdd_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareAdd_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareAdd_level, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareAdd_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_NetShareInfo(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareAdd_info, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareAdd_parm_error(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareAdd_parm_error_, NDR_POINTER_UNIQUE, "Pointer to Parm Error (uint32)",hf_srvsvc_srvsvc_NetShareAdd_parm_error);

	return offset;
}

static int
srvsvc_dissect_element_NetShareAdd_parm_error_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareAdd_parm_error, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetShareAdd( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [in] uint32 level, */
/* IDL: [in] [switch_is(level)] srvsvc_NetShareInfo info, */
/* IDL: [unique(1)] [out] [in] uint32 *parm_error */
/* IDL: ); */

static int
srvsvc_dissect_NetShareAdd_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetShareAdd";
	offset = srvsvc_dissect_element_NetShareAdd_parm_error(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetShareAdd_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetShareAdd";
	offset = srvsvc_dissect_element_NetShareAdd_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetShareAdd_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetShareAdd_info(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetShareAdd_parm_error(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetShareEnumAll_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareEnumAll_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetShareEnumAll_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetShareEnumAll_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareEnumAll_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareEnumAll_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareEnumAll_level_, NDR_POINTER_REF, "Pointer to Level (uint32)",hf_srvsvc_srvsvc_NetShareEnumAll_level);

	return offset;
}

static int
srvsvc_dissect_element_NetShareEnumAll_level_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareEnumAll_level, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareEnumAll_ctr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareEnumAll_ctr_, NDR_POINTER_REF, "Pointer to Ctr (srvsvc_NetShareCtr)",hf_srvsvc_srvsvc_NetShareEnumAll_ctr);

	return offset;
}

static int
srvsvc_dissect_element_NetShareEnumAll_ctr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_NetShareCtr(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareEnumAll_ctr, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareEnumAll_max_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareEnumAll_max_buffer, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareEnumAll_totalentries(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareEnumAll_totalentries_, NDR_POINTER_REF, "Pointer to Totalentries (uint32)",hf_srvsvc_srvsvc_NetShareEnumAll_totalentries);

	return offset;
}

static int
srvsvc_dissect_element_NetShareEnumAll_totalentries_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareEnumAll_totalentries, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareEnumAll_resume_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareEnumAll_resume_handle_, NDR_POINTER_UNIQUE, "Pointer to Resume Handle (uint32)",hf_srvsvc_srvsvc_NetShareEnumAll_resume_handle);

	return offset;
}

static int
srvsvc_dissect_element_NetShareEnumAll_resume_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareEnumAll_resume_handle, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetShareEnumAll( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [out] [in] [ref] uint32 *level, */
/* IDL: [out] [in] [ref] [switch_is(level)] srvsvc_NetShareCtr *ctr, */
/* IDL: [in] uint32 max_buffer, */
/* IDL: [out] [ref] uint32 *totalentries, */
/* IDL: [unique(1)] [out] [in] uint32 *resume_handle */
/* IDL: ); */

static int
srvsvc_dissect_NetShareEnumAll_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetShareEnumAll";
	offset = srvsvc_dissect_element_NetShareEnumAll_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = srvsvc_dissect_element_NetShareEnumAll_ctr(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = srvsvc_dissect_element_NetShareEnumAll_totalentries(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = srvsvc_dissect_element_NetShareEnumAll_resume_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetShareEnumAll_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetShareEnumAll";
	offset = srvsvc_dissect_element_NetShareEnumAll_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetShareEnumAll_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetShareEnumAll_ctr(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetShareEnumAll_max_buffer(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetShareEnumAll_resume_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetShareGetInfo_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareGetInfo_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetShareGetInfo_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetShareGetInfo_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareGetInfo_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareGetInfo_share_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareGetInfo_share_name, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareGetInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareGetInfo_level, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareGetInfo_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareGetInfo_info_, NDR_POINTER_REF, "Pointer to Info (srvsvc_NetShareInfo)",hf_srvsvc_srvsvc_NetShareGetInfo_info);

	return offset;
}

static int
srvsvc_dissect_element_NetShareGetInfo_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_NetShareInfo(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareGetInfo_info, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetShareGetInfo( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [in] [charset(UTF16)] uint16 share_name[*], */
/* IDL: [in] uint32 level, */
/* IDL: [out] [ref] [switch_is(level)] srvsvc_NetShareInfo *info */
/* IDL: ); */

static int
srvsvc_dissect_NetShareGetInfo_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetShareGetInfo";
	offset = srvsvc_dissect_element_NetShareGetInfo_info(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetShareGetInfo_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetShareGetInfo";
	offset = srvsvc_dissect_element_NetShareGetInfo_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetShareGetInfo_share_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetShareGetInfo_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetShareSetInfo_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareSetInfo_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetShareSetInfo_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetShareSetInfo_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareSetInfo_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareSetInfo_share_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareSetInfo_share_name, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareSetInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareSetInfo_level, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareSetInfo_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_NetShareInfo(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareSetInfo_info, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareSetInfo_parm_error(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareSetInfo_parm_error_, NDR_POINTER_UNIQUE, "Pointer to Parm Error (uint32)",hf_srvsvc_srvsvc_NetShareSetInfo_parm_error);

	return offset;
}

static int
srvsvc_dissect_element_NetShareSetInfo_parm_error_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareSetInfo_parm_error, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetShareSetInfo( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [in] [charset(UTF16)] uint16 share_name[*], */
/* IDL: [in] uint32 level, */
/* IDL: [in] [switch_is(level)] srvsvc_NetShareInfo info, */
/* IDL: [unique(1)] [out] [in] uint32 *parm_error */
/* IDL: ); */

static int
srvsvc_dissect_NetShareSetInfo_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetShareSetInfo";
	offset = srvsvc_dissect_element_NetShareSetInfo_parm_error(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetShareSetInfo_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetShareSetInfo";
	offset = srvsvc_dissect_element_NetShareSetInfo_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetShareSetInfo_share_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetShareSetInfo_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetShareSetInfo_info(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetShareSetInfo_parm_error(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetShareDel_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareDel_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetShareDel_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetShareDel_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareDel_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareDel_share_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareDel_share_name, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareDel_reserved(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareDel_reserved, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetShareDel( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [in] [charset(UTF16)] uint16 share_name[*], */
/* IDL: [in] uint32 reserved */
/* IDL: ); */

static int
srvsvc_dissect_NetShareDel_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetShareDel";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetShareDel_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetShareDel";
	offset = srvsvc_dissect_element_NetShareDel_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetShareDel_share_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetShareDel_reserved(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetShareDelSticky_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareDelSticky_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetShareDelSticky_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetShareDelSticky_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareDelSticky_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareDelSticky_share_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareDelSticky_share_name, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareDelSticky_reserved(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareDelSticky_reserved, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetShareDelSticky( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [in] [charset(UTF16)] uint16 share_name[*], */
/* IDL: [in] uint32 reserved */
/* IDL: ); */

static int
srvsvc_dissect_NetShareDelSticky_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetShareDelSticky";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetShareDelSticky_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetShareDelSticky";
	offset = srvsvc_dissect_element_NetShareDelSticky_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetShareDelSticky_share_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetShareDelSticky_reserved(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetShareCheck_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCheck_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetShareCheck_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCheck_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareCheck_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCheck_device_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareCheck_device_name, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCheck_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareCheck_type_, NDR_POINTER_REF, "Pointer to Type (srvsvc_ShareType)",hf_srvsvc_srvsvc_NetShareCheck_type);

	return offset;
}

static int
srvsvc_dissect_element_NetShareCheck_type_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_enum_ShareType(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareCheck_type, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetShareCheck( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [in] [charset(UTF16)] uint16 device_name[*], */
/* IDL: [out] [ref] srvsvc_ShareType *type */
/* IDL: ); */

static int
srvsvc_dissect_NetShareCheck_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetShareCheck";
	offset = srvsvc_dissect_element_NetShareCheck_type(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetShareCheck_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetShareCheck";
	offset = srvsvc_dissect_element_NetShareCheck_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetShareCheck_device_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetSrvGetInfo_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvGetInfo_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetSrvGetInfo_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvGetInfo_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSrvGetInfo_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvGetInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvGetInfo_level, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvGetInfo_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvGetInfo_info_, NDR_POINTER_REF, "Pointer to Info (srvsvc_NetSrvInfo)",hf_srvsvc_srvsvc_NetSrvGetInfo_info);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvGetInfo_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_NetSrvInfo(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvGetInfo_info, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetSrvGetInfo( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [in] uint32 level, */
/* IDL: [out] [ref] [switch_is(level)] srvsvc_NetSrvInfo *info */
/* IDL: ); */

static int
srvsvc_dissect_NetSrvGetInfo_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetSrvGetInfo";
	offset = srvsvc_dissect_element_NetSrvGetInfo_info(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetSrvGetInfo_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetSrvGetInfo";
	offset = srvsvc_dissect_element_NetSrvGetInfo_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetSrvGetInfo_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetSrvSetInfo_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvSetInfo_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetSrvSetInfo_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvSetInfo_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSrvSetInfo_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvSetInfo_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvSetInfo_level, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvSetInfo_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_NetSrvInfo(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvSetInfo_info, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvSetInfo_parm_error(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSrvSetInfo_parm_error_, NDR_POINTER_UNIQUE, "Pointer to Parm Error (uint32)",hf_srvsvc_srvsvc_NetSrvSetInfo_parm_error);

	return offset;
}

static int
srvsvc_dissect_element_NetSrvSetInfo_parm_error_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSrvSetInfo_parm_error, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetSrvSetInfo( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [in] uint32 level, */
/* IDL: [in] [switch_is(level)] srvsvc_NetSrvInfo info, */
/* IDL: [unique(1)] [out] [in] uint32 *parm_error */
/* IDL: ); */

static int
srvsvc_dissect_NetSrvSetInfo_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetSrvSetInfo";
	offset = srvsvc_dissect_element_NetSrvSetInfo_parm_error(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetSrvSetInfo_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetSrvSetInfo";
	offset = srvsvc_dissect_element_NetSrvSetInfo_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetSrvSetInfo_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetSrvSetInfo_info(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetSrvSetInfo_parm_error(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetDiskEnum_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetDiskEnum_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetDiskEnum_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetDiskEnum_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetDiskEnum_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetDiskEnum_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetDiskEnum_level, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetDiskEnum_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetDiskEnum_info_, NDR_POINTER_REF, "Pointer to Info (srvsvc_NetDiskInfo)",hf_srvsvc_srvsvc_NetDiskEnum_info);

	return offset;
}

static int
srvsvc_dissect_element_NetDiskEnum_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetDiskInfo(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetDiskEnum_info,0);

	return offset;
}

static int
srvsvc_dissect_element_NetDiskEnum_maxlen(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetDiskEnum_maxlen, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetDiskEnum_totalentries(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetDiskEnum_totalentries_, NDR_POINTER_REF, "Pointer to Totalentries (uint32)",hf_srvsvc_srvsvc_NetDiskEnum_totalentries);

	return offset;
}

static int
srvsvc_dissect_element_NetDiskEnum_totalentries_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetDiskEnum_totalentries, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetDiskEnum_resume_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetDiskEnum_resume_handle_, NDR_POINTER_UNIQUE, "Pointer to Resume Handle (uint32)",hf_srvsvc_srvsvc_NetDiskEnum_resume_handle);

	return offset;
}

static int
srvsvc_dissect_element_NetDiskEnum_resume_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetDiskEnum_resume_handle, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetDiskEnum( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [in] uint32 level, */
/* IDL: [out] [in] [ref] srvsvc_NetDiskInfo *info, */
/* IDL: [in] uint32 maxlen, */
/* IDL: [out] [ref] uint32 *totalentries, */
/* IDL: [unique(1)] [out] [in] uint32 *resume_handle */
/* IDL: ); */

static int
srvsvc_dissect_NetDiskEnum_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetDiskEnum";
	offset = srvsvc_dissect_element_NetDiskEnum_info(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = srvsvc_dissect_element_NetDiskEnum_totalentries(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = srvsvc_dissect_element_NetDiskEnum_resume_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetDiskEnum_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetDiskEnum";
	offset = srvsvc_dissect_element_NetDiskEnum_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetDiskEnum_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetDiskEnum_info(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetDiskEnum_maxlen(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetDiskEnum_resume_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetServerStatisticsGet_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetServerStatisticsGet_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetServerStatisticsGet_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetServerStatisticsGet_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetServerStatisticsGet_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetServerStatisticsGet_service(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetServerStatisticsGet_service_, NDR_POINTER_UNIQUE, "Pointer to Service (uint16)",hf_srvsvc_srvsvc_NetServerStatisticsGet_service);

	return offset;
}

static int
srvsvc_dissect_element_NetServerStatisticsGet_service_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetServerStatisticsGet_service, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetServerStatisticsGet_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetServerStatisticsGet_level, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetServerStatisticsGet_options(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetServerStatisticsGet_options, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetServerStatisticsGet_stat(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetServerStatisticsGet_stat_, NDR_POINTER_REF, "Pointer to Stat (srvsvc_Statistics)",hf_srvsvc_srvsvc_NetServerStatisticsGet_stat);

	return offset;
}

static int
srvsvc_dissect_element_NetServerStatisticsGet_stat_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_Statistics(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetServerStatisticsGet_stat,0);

	return offset;
}

/* IDL: WERROR srvsvc_NetServerStatisticsGet( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *service, */
/* IDL: [in] uint32 level, */
/* IDL: [in] uint32 options, */
/* IDL: [out] [ref] srvsvc_Statistics *stat */
/* IDL: ); */

static int
srvsvc_dissect_NetServerStatisticsGet_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetServerStatisticsGet";
	offset = srvsvc_dissect_element_NetServerStatisticsGet_stat(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetServerStatisticsGet_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetServerStatisticsGet";
	offset = srvsvc_dissect_element_NetServerStatisticsGet_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetServerStatisticsGet_service(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetServerStatisticsGet_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetServerStatisticsGet_options(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetTransportAdd_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportAdd_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetTransportAdd_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportAdd_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetTransportAdd_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportAdd_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportAdd_level, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportAdd_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_NetTransportInfo(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportAdd_info, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetTransportAdd( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [in] uint32 level, */
/* IDL: [in] [switch_is(level)] srvsvc_NetTransportInfo info */
/* IDL: ); */

static int
srvsvc_dissect_NetTransportAdd_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetTransportAdd";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetTransportAdd_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetTransportAdd";
	offset = srvsvc_dissect_element_NetTransportAdd_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetTransportAdd_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetTransportAdd_info(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetTransportEnum_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportEnum_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetTransportEnum_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportEnum_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetTransportEnum_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportEnum_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportEnum_level_, NDR_POINTER_REF, "Pointer to Level (uint32)",hf_srvsvc_srvsvc_NetTransportEnum_level);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportEnum_level_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportEnum_level, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportEnum_transports(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportEnum_transports_, NDR_POINTER_REF, "Pointer to Transports (srvsvc_NetTransportCtr)",hf_srvsvc_srvsvc_NetTransportEnum_transports);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportEnum_transports_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_NetTransportCtr(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportEnum_transports, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportEnum_max_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportEnum_max_buffer, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportEnum_totalentries(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportEnum_totalentries_, NDR_POINTER_REF, "Pointer to Totalentries (uint32)",hf_srvsvc_srvsvc_NetTransportEnum_totalentries);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportEnum_totalentries_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportEnum_totalentries, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportEnum_resume_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportEnum_resume_handle_, NDR_POINTER_UNIQUE, "Pointer to Resume Handle (uint32)",hf_srvsvc_srvsvc_NetTransportEnum_resume_handle);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportEnum_resume_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportEnum_resume_handle, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetTransportEnum( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [out] [in] [ref] uint32 *level, */
/* IDL: [out] [in] [ref] [switch_is(level)] srvsvc_NetTransportCtr *transports, */
/* IDL: [in] uint32 max_buffer, */
/* IDL: [out] [ref] uint32 *totalentries, */
/* IDL: [unique(1)] [out] [in] uint32 *resume_handle */
/* IDL: ); */

static int
srvsvc_dissect_NetTransportEnum_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetTransportEnum";
	offset = srvsvc_dissect_element_NetTransportEnum_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = srvsvc_dissect_element_NetTransportEnum_transports(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = srvsvc_dissect_element_NetTransportEnum_totalentries(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = srvsvc_dissect_element_NetTransportEnum_resume_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetTransportEnum_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetTransportEnum";
	offset = srvsvc_dissect_element_NetTransportEnum_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetTransportEnum_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetTransportEnum_transports(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetTransportEnum_max_buffer(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetTransportEnum_resume_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetTransportDel_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetTransportDel_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetTransportDel_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportDel_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetTransportDel_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportDel_unknown(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetTransportDel_unknown, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetTransportDel_transport(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetTransportInfo0(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetTransportDel_transport,0);

	return offset;
}

/* IDL: WERROR srvsvc_NetTransportDel( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [in] uint32 unknown, */
/* IDL: [in] srvsvc_NetTransportInfo0 transport */
/* IDL: ); */

static int
srvsvc_dissect_NetTransportDel_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetTransportDel";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetTransportDel_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetTransportDel";
	offset = srvsvc_dissect_element_NetTransportDel_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetTransportDel_unknown(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetTransportDel_transport(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetRemoteTOD_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetRemoteTOD_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetRemoteTOD_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetRemoteTOD_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetRemoteTOD_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetRemoteTOD_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetRemoteTOD_info_, NDR_POINTER_UNIQUE, "Pointer to Info (srvsvc_NetRemoteTODInfo)",hf_srvsvc_srvsvc_NetRemoteTOD_info);

	return offset;
}

static int
srvsvc_dissect_element_NetRemoteTOD_info_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_struct_NetRemoteTODInfo(tvb,offset,pinfo,tree,drep,hf_srvsvc_srvsvc_NetRemoteTOD_info,0);

	return offset;
}

/* IDL: WERROR srvsvc_NetRemoteTOD( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [out] [unique(1)] srvsvc_NetRemoteTODInfo *info */
/* IDL: ); */

static int
srvsvc_dissect_NetRemoteTOD_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetRemoteTOD";
	offset = srvsvc_dissect_element_NetRemoteTOD_info(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetRemoteTOD_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetRemoteTOD";
	offset = srvsvc_dissect_element_NetRemoteTOD_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetSetServiceBits_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSetServiceBits_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetSetServiceBits_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetSetServiceBits_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSetServiceBits_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSetServiceBits_transport(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSetServiceBits_transport_, NDR_POINTER_UNIQUE, "Pointer to Transport (uint16)",hf_srvsvc_srvsvc_NetSetServiceBits_transport);

	return offset;
}

static int
srvsvc_dissect_element_NetSetServiceBits_transport_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSetServiceBits_transport, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSetServiceBits_servicebits(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSetServiceBits_servicebits, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSetServiceBits_updateimmediately(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetSetServiceBits_updateimmediately, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetSetServiceBits( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *transport, */
/* IDL: [in] uint32 servicebits, */
/* IDL: [in] uint32 updateimmediately */
/* IDL: ); */

static int
srvsvc_dissect_NetSetServiceBits_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetSetServiceBits";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetSetServiceBits_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetSetServiceBits";
	offset = srvsvc_dissect_element_NetSetServiceBits_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetSetServiceBits_transport(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetSetServiceBits_servicebits(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetSetServiceBits_updateimmediately(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetPathType_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetPathType_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetPathType_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetPathType_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetPathType_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetPathType_path(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetPathType_path, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetPathType_pathflags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetPathType_pathflags, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetPathType_pathtype(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetPathType_pathtype_, NDR_POINTER_REF, "Pointer to Pathtype (uint32)",hf_srvsvc_srvsvc_NetPathType_pathtype);

	return offset;
}

static int
srvsvc_dissect_element_NetPathType_pathtype_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetPathType_pathtype, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetPathType( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [in] [charset(UTF16)] uint16 path[*], */
/* IDL: [in] uint32 pathflags, */
/* IDL: [out] [ref] uint32 *pathtype */
/* IDL: ); */

static int
srvsvc_dissect_NetPathType_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetPathType";
	offset = srvsvc_dissect_element_NetPathType_pathtype(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetPathType_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetPathType";
	offset = srvsvc_dissect_element_NetPathType_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetPathType_path(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetPathType_pathflags(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetPathCanonicalize_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetPathCanonicalize_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetPathCanonicalize_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetPathCanonicalize_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetPathCanonicalize_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetPathCanonicalize_path(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetPathCanonicalize_path, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetPathCanonicalize_can_path(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetPathCanonicalize_can_path_);

	return offset;
}

static int
srvsvc_dissect_element_NetPathCanonicalize_can_path_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetPathCanonicalize_can_path, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetPathCanonicalize_maxbuf(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetPathCanonicalize_maxbuf, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetPathCanonicalize_prefix(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetPathCanonicalize_prefix, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetPathCanonicalize_pathtype(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetPathCanonicalize_pathtype_, NDR_POINTER_REF, "Pointer to Pathtype (uint32)",hf_srvsvc_srvsvc_NetPathCanonicalize_pathtype);

	return offset;
}

static int
srvsvc_dissect_element_NetPathCanonicalize_pathtype_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetPathCanonicalize_pathtype, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetPathCanonicalize_pathflags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetPathCanonicalize_pathflags, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetPathCanonicalize( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [in] [charset(UTF16)] uint16 path[*], */
/* IDL: [out] [size_is(maxbuf)] uint8 can_path[*], */
/* IDL: [in] uint32 maxbuf, */
/* IDL: [in] [charset(UTF16)] uint16 prefix[*], */
/* IDL: [out] [in] [ref] uint32 *pathtype, */
/* IDL: [in] uint32 pathflags */
/* IDL: ); */

static int
srvsvc_dissect_NetPathCanonicalize_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetPathCanonicalize";
	offset = srvsvc_dissect_element_NetPathCanonicalize_can_path(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = srvsvc_dissect_element_NetPathCanonicalize_pathtype(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetPathCanonicalize_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetPathCanonicalize";
	offset = srvsvc_dissect_element_NetPathCanonicalize_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetPathCanonicalize_path(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetPathCanonicalize_maxbuf(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetPathCanonicalize_prefix(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetPathCanonicalize_pathtype(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetPathCanonicalize_pathflags(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetPathCompare_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetPathCompare_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetPathCompare_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetPathCompare_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetPathCompare_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetPathCompare_path1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetPathCompare_path1, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetPathCompare_path2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetPathCompare_path2, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetPathCompare_pathtype(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetPathCompare_pathtype, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetPathCompare_pathflags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetPathCompare_pathflags, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetPathCompare( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [in] [charset(UTF16)] uint16 path1[*], */
/* IDL: [in] [charset(UTF16)] uint16 path2[*], */
/* IDL: [in] uint32 pathtype, */
/* IDL: [in] uint32 pathflags */
/* IDL: ); */

static int
srvsvc_dissect_NetPathCompare_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetPathCompare";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetPathCompare_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetPathCompare";
	offset = srvsvc_dissect_element_NetPathCompare_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetPathCompare_path1(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetPathCompare_path2(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetPathCompare_pathtype(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetPathCompare_pathflags(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetNameValidate_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetNameValidate_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetNameValidate_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetNameValidate_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetNameValidate_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetNameValidate_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetNameValidate_name, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetNameValidate_name_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetNameValidate_name_type, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetNameValidate_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetNameValidate_flags, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetNameValidate( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [in] [charset(UTF16)] uint16 name[*], */
/* IDL: [in] uint32 name_type, */
/* IDL: [in] uint32 flags */
/* IDL: ); */

static int
srvsvc_dissect_NetNameValidate_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetNameValidate";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetNameValidate_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetNameValidate";
	offset = srvsvc_dissect_element_NetNameValidate_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetNameValidate_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetNameValidate_name_type(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetNameValidate_flags(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

/* IDL: WERROR srvsvc_NETRPRNAMECANONICALIZE( */
/* IDL:  */
/* IDL: ); */

static int
srvsvc_dissect_NETRPRNAMECANONICALIZE_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NETRPRNAMECANONICALIZE";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NETRPRNAMECANONICALIZE_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NETRPRNAMECANONICALIZE";
	return offset;
}

static int
srvsvc_dissect_element_NetPRNameCompare_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetPRNameCompare_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetPRNameCompare_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetPRNameCompare_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetPRNameCompare_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetPRNameCompare_name1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetPRNameCompare_name1, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetPRNameCompare_name2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetPRNameCompare_name2, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetPRNameCompare_name_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetPRNameCompare_name_type, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetPRNameCompare_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetPRNameCompare_flags, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetPRNameCompare( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [in] [charset(UTF16)] uint16 name1[*], */
/* IDL: [in] [charset(UTF16)] uint16 name2[*], */
/* IDL: [in] uint32 name_type, */
/* IDL: [in] uint32 flags */
/* IDL: ); */

static int
srvsvc_dissect_NetPRNameCompare_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetPRNameCompare";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetPRNameCompare_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetPRNameCompare";
	offset = srvsvc_dissect_element_NetPRNameCompare_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetPRNameCompare_name1(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetPRNameCompare_name2(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetPRNameCompare_name_type(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetPRNameCompare_flags(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetShareEnum_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareEnum_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetShareEnum_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetShareEnum_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareEnum_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareEnum_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareEnum_level_, NDR_POINTER_REF, "Pointer to Level (uint32)",hf_srvsvc_srvsvc_NetShareEnum_level);

	return offset;
}

static int
srvsvc_dissect_element_NetShareEnum_level_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareEnum_level, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareEnum_ctr(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareEnum_ctr_, NDR_POINTER_REF, "Pointer to Ctr (srvsvc_NetShareCtr)",hf_srvsvc_srvsvc_NetShareEnum_ctr);

	return offset;
}

static int
srvsvc_dissect_element_NetShareEnum_ctr_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_NetShareCtr(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareEnum_ctr, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareEnum_max_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareEnum_max_buffer, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareEnum_totalentries(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareEnum_totalentries_, NDR_POINTER_REF, "Pointer to Totalentries (uint32)",hf_srvsvc_srvsvc_NetShareEnum_totalentries);

	return offset;
}

static int
srvsvc_dissect_element_NetShareEnum_totalentries_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareEnum_totalentries, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareEnum_resume_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareEnum_resume_handle_, NDR_POINTER_UNIQUE, "Pointer to Resume Handle (uint32)",hf_srvsvc_srvsvc_NetShareEnum_resume_handle);

	return offset;
}

static int
srvsvc_dissect_element_NetShareEnum_resume_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareEnum_resume_handle, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetShareEnum( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [out] [in] [ref] uint32 *level, */
/* IDL: [out] [in] [ref] [switch_is(level)] srvsvc_NetShareCtr *ctr, */
/* IDL: [in] uint32 max_buffer, */
/* IDL: [out] [ref] uint32 *totalentries, */
/* IDL: [unique(1)] [out] [in] uint32 *resume_handle */
/* IDL: ); */

static int
srvsvc_dissect_NetShareEnum_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetShareEnum";
	offset = srvsvc_dissect_element_NetShareEnum_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = srvsvc_dissect_element_NetShareEnum_ctr(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = srvsvc_dissect_element_NetShareEnum_totalentries(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = srvsvc_dissect_element_NetShareEnum_resume_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetShareEnum_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetShareEnum";
	offset = srvsvc_dissect_element_NetShareEnum_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetShareEnum_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetShareEnum_ctr(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetShareEnum_max_buffer(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetShareEnum_resume_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetShareDelStart_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareDelStart_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetShareDelStart_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetShareDelStart_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareDelStart_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareDelStart_share(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetShareDelStart_share, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareDelStart_reserved(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareDelStart_reserved, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetShareDelStart_hnd(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareDelStart_hnd_, NDR_POINTER_UNIQUE, "Pointer to Hnd (policy_handle)",hf_srvsvc_srvsvc_NetShareDelStart_hnd);

	return offset;
}

static int
srvsvc_dissect_element_NetShareDelStart_hnd_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareDelStart_hnd, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetShareDelStart( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [in] [charset(UTF16)] uint16 share[*], */
/* IDL: [in] uint32 reserved, */
/* IDL: [out] [unique(1)] policy_handle *hnd */
/* IDL: ); */

static int
srvsvc_dissect_NetShareDelStart_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetShareDelStart";
	offset = srvsvc_dissect_element_NetShareDelStart_hnd(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetShareDelStart_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetShareDelStart";
	offset = srvsvc_dissect_element_NetShareDelStart_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetShareDelStart_share(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetShareDelStart_reserved(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetShareDelCommit_hnd(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetShareDelCommit_hnd_, NDR_POINTER_UNIQUE, "Pointer to Hnd (policy_handle)",hf_srvsvc_srvsvc_NetShareDelCommit_hnd);

	return offset;
}

static int
srvsvc_dissect_element_NetShareDelCommit_hnd_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetShareDelCommit_hnd, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetShareDelCommit( */
/* IDL: [unique(1)] [out] [in] policy_handle *hnd */
/* IDL: ); */

static int
srvsvc_dissect_NetShareDelCommit_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetShareDelCommit";
	offset = srvsvc_dissect_element_NetShareDelCommit_hnd(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetShareDelCommit_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetShareDelCommit";
	offset = srvsvc_dissect_element_NetShareDelCommit_hnd(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetGetFileSecurity_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetGetFileSecurity_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetGetFileSecurity_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetGetFileSecurity_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetGetFileSecurity_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetGetFileSecurity_share(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetGetFileSecurity_share_, NDR_POINTER_UNIQUE, "Pointer to Share (uint16)",hf_srvsvc_srvsvc_NetGetFileSecurity_share);

	return offset;
}

static int
srvsvc_dissect_element_NetGetFileSecurity_share_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetGetFileSecurity_share, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetGetFileSecurity_file(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetGetFileSecurity_file, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetGetFileSecurity_sd_buf(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetGetFileSecurity_sd_buf_, NDR_POINTER_UNIQUE, "Pointer to Sd Buf (sec_desc_buf)",hf_srvsvc_srvsvc_NetGetFileSecurity_sd_buf);

	return offset;
}

/* IDL: WERROR srvsvc_NetGetFileSecurity( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *share, */
/* IDL: [in] [charset(UTF16)] uint16 file[*], */
/* IDL: [in] security_secinfo securityinformation, */
/* IDL: [out] [unique(1)] sec_desc_buf *sd_buf */
/* IDL: ); */

static int
srvsvc_dissect_NetGetFileSecurity_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetGetFileSecurity";
	offset = srvsvc_dissect_element_NetGetFileSecurity_sd_buf(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetGetFileSecurity_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetGetFileSecurity";
	offset = srvsvc_dissect_element_NetGetFileSecurity_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetGetFileSecurity_share(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetGetFileSecurity_file(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetGetFileSecurity_securityinformation(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetSetFileSecurity_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSetFileSecurity_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetSetFileSecurity_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetSetFileSecurity_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSetFileSecurity_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSetFileSecurity_share(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetSetFileSecurity_share_, NDR_POINTER_UNIQUE, "Pointer to Share (uint16)",hf_srvsvc_srvsvc_NetSetFileSecurity_share);

	return offset;
}

static int
srvsvc_dissect_element_NetSetFileSecurity_share_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSetFileSecurity_share, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetSetFileSecurity_file(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetSetFileSecurity_file, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetSetFileSecurity( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *share, */
/* IDL: [in] [charset(UTF16)] uint16 file[*], */
/* IDL: [in] security_secinfo securityinformation, */
/* IDL: [in] sec_desc_buf sd_buf */
/* IDL: ); */

static int
srvsvc_dissect_NetSetFileSecurity_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetSetFileSecurity";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetSetFileSecurity_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetSetFileSecurity";
	offset = srvsvc_dissect_element_NetSetFileSecurity_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetSetFileSecurity_share(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetSetFileSecurity_file(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetSetFileSecurity_securityinformation(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetSetFileSecurity_sd_buf(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetServerTransportAddEx_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetServerTransportAddEx_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetServerTransportAddEx_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetServerTransportAddEx_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetServerTransportAddEx_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetServerTransportAddEx_level(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetServerTransportAddEx_level, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetServerTransportAddEx_info(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = srvsvc_dissect_NetTransportInfo(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetServerTransportAddEx_info, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetServerTransportAddEx( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [in] uint32 level, */
/* IDL: [in] [switch_is(level)] srvsvc_NetTransportInfo info */
/* IDL: ); */

static int
srvsvc_dissect_NetServerTransportAddEx_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetServerTransportAddEx";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetServerTransportAddEx_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetServerTransportAddEx";
	offset = srvsvc_dissect_element_NetServerTransportAddEx_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetServerTransportAddEx_level(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetServerTransportAddEx_info(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
srvsvc_dissect_element_NetServerSetServiceBitsEx_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetServerSetServiceBitsEx_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Server Unc (uint16)",hf_srvsvc_srvsvc_NetServerSetServiceBitsEx_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetServerSetServiceBitsEx_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetServerSetServiceBitsEx_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetServerSetServiceBitsEx_emulated_server_unc(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetServerSetServiceBitsEx_emulated_server_unc_, NDR_POINTER_UNIQUE, "Pointer to Emulated Server Unc (uint16)",hf_srvsvc_srvsvc_NetServerSetServiceBitsEx_emulated_server_unc);

	return offset;
}

static int
srvsvc_dissect_element_NetServerSetServiceBitsEx_emulated_server_unc_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetServerSetServiceBitsEx_emulated_server_unc, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetServerSetServiceBitsEx_transport(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, srvsvc_dissect_element_NetServerSetServiceBitsEx_transport_, NDR_POINTER_UNIQUE, "Pointer to Transport (uint16)",hf_srvsvc_srvsvc_NetServerSetServiceBitsEx_transport);

	return offset;
}

static int
srvsvc_dissect_element_NetServerSetServiceBitsEx_transport_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_srvsvc_srvsvc_NetServerSetServiceBitsEx_transport, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetServerSetServiceBitsEx_servicebitsofinterest(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetServerSetServiceBitsEx_servicebitsofinterest, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetServerSetServiceBitsEx_servicebits(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetServerSetServiceBitsEx_servicebits, 0);

	return offset;
}

static int
srvsvc_dissect_element_NetServerSetServiceBitsEx_updateimmediately(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_srvsvc_NetServerSetServiceBitsEx_updateimmediately, 0);

	return offset;
}

/* IDL: WERROR srvsvc_NetServerSetServiceBitsEx( */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *server_unc, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *emulated_server_unc, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *transport, */
/* IDL: [in] uint32 servicebitsofinterest, */
/* IDL: [in] uint32 servicebits, */
/* IDL: [in] uint32 updateimmediately */
/* IDL: ); */

static int
srvsvc_dissect_NetServerSetServiceBitsEx_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NetServerSetServiceBitsEx";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NetServerSetServiceBitsEx_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NetServerSetServiceBitsEx";
	offset = srvsvc_dissect_element_NetServerSetServiceBitsEx_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetServerSetServiceBitsEx_emulated_server_unc(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetServerSetServiceBitsEx_transport(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetServerSetServiceBitsEx_servicebitsofinterest(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetServerSetServiceBitsEx_servicebits(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = srvsvc_dissect_element_NetServerSetServiceBitsEx_updateimmediately(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

/* IDL: WERROR srvsvc_NETRDFSGETVERSION( */
/* IDL:  */
/* IDL: ); */

static int
srvsvc_dissect_NETRDFSGETVERSION_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NETRDFSGETVERSION";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NETRDFSGETVERSION_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NETRDFSGETVERSION";
	return offset;
}

/* IDL: WERROR srvsvc_NETRDFSCREATELOCALPARTITION( */
/* IDL:  */
/* IDL: ); */

static int
srvsvc_dissect_NETRDFSCREATELOCALPARTITION_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NETRDFSCREATELOCALPARTITION";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NETRDFSCREATELOCALPARTITION_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NETRDFSCREATELOCALPARTITION";
	return offset;
}

/* IDL: WERROR srvsvc_NETRDFSDELETELOCALPARTITION( */
/* IDL:  */
/* IDL: ); */

static int
srvsvc_dissect_NETRDFSDELETELOCALPARTITION_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NETRDFSDELETELOCALPARTITION";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NETRDFSDELETELOCALPARTITION_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NETRDFSDELETELOCALPARTITION";
	return offset;
}

/* IDL: WERROR srvsvc_NETRDFSSETLOCALVOLUMESTATE( */
/* IDL:  */
/* IDL: ); */

static int
srvsvc_dissect_NETRDFSSETLOCALVOLUMESTATE_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NETRDFSSETLOCALVOLUMESTATE";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NETRDFSSETLOCALVOLUMESTATE_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NETRDFSSETLOCALVOLUMESTATE";
	return offset;
}

/* IDL: WERROR srvsvc_NETRDFSSETSERVERINFO( */
/* IDL:  */
/* IDL: ); */

static int
srvsvc_dissect_NETRDFSSETSERVERINFO_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NETRDFSSETSERVERINFO";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NETRDFSSETSERVERINFO_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NETRDFSSETSERVERINFO";
	return offset;
}

/* IDL: WERROR srvsvc_NETRDFSCREATEEXITPOINT( */
/* IDL:  */
/* IDL: ); */

static int
srvsvc_dissect_NETRDFSCREATEEXITPOINT_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NETRDFSCREATEEXITPOINT";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NETRDFSCREATEEXITPOINT_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NETRDFSCREATEEXITPOINT";
	return offset;
}

/* IDL: WERROR srvsvc_NETRDFSDELETEEXITPOINT( */
/* IDL:  */
/* IDL: ); */

static int
srvsvc_dissect_NETRDFSDELETEEXITPOINT_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NETRDFSDELETEEXITPOINT";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NETRDFSDELETEEXITPOINT_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NETRDFSDELETEEXITPOINT";
	return offset;
}

/* IDL: WERROR srvsvc_NETRDFSMODIFYPREFIX( */
/* IDL:  */
/* IDL: ); */

static int
srvsvc_dissect_NETRDFSMODIFYPREFIX_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NETRDFSMODIFYPREFIX";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NETRDFSMODIFYPREFIX_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NETRDFSMODIFYPREFIX";
	return offset;
}

/* IDL: WERROR srvsvc_NETRDFSFIXLOCALVOLUME( */
/* IDL:  */
/* IDL: ); */

static int
srvsvc_dissect_NETRDFSFIXLOCALVOLUME_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NETRDFSFIXLOCALVOLUME";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NETRDFSFIXLOCALVOLUME_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NETRDFSFIXLOCALVOLUME";
	return offset;
}

/* IDL: WERROR srvsvc_NETRDFSMANAGERREPORTSITEINFO( */
/* IDL:  */
/* IDL: ); */

static int
srvsvc_dissect_NETRDFSMANAGERREPORTSITEINFO_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NETRDFSMANAGERREPORTSITEINFO";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NETRDFSMANAGERREPORTSITEINFO_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NETRDFSMANAGERREPORTSITEINFO";
	return offset;
}

/* IDL: WERROR srvsvc_NETRSERVERTRANSPORTDELEX( */
/* IDL:  */
/* IDL: ); */

static int
srvsvc_dissect_NETRSERVERTRANSPORTDELEX_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="NETRSERVERTRANSPORTDELEX";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
srvsvc_dissect_NETRSERVERTRANSPORTDELEX_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="NETRSERVERTRANSPORTDELEX";
	return offset;
}


static dcerpc_sub_dissector srvsvc_dissectors[] = {
	{ 0, "NetCharDevEnum",
	   srvsvc_dissect_NetCharDevEnum_request, srvsvc_dissect_NetCharDevEnum_response},
	{ 1, "NetCharDevGetInfo",
	   srvsvc_dissect_NetCharDevGetInfo_request, srvsvc_dissect_NetCharDevGetInfo_response},
	{ 2, "NetCharDevControl",
	   srvsvc_dissect_NetCharDevControl_request, srvsvc_dissect_NetCharDevControl_response},
	{ 3, "NetCharDevQEnum",
	   srvsvc_dissect_NetCharDevQEnum_request, srvsvc_dissect_NetCharDevQEnum_response},
	{ 4, "NetCharDevQGetInfo",
	   srvsvc_dissect_NetCharDevQGetInfo_request, srvsvc_dissect_NetCharDevQGetInfo_response},
	{ 5, "NetCharDevQSetInfo",
	   srvsvc_dissect_NetCharDevQSetInfo_request, srvsvc_dissect_NetCharDevQSetInfo_response},
	{ 6, "NetCharDevQPurge",
	   srvsvc_dissect_NetCharDevQPurge_request, srvsvc_dissect_NetCharDevQPurge_response},
	{ 7, "NetCharDevQPurgeSelf",
	   srvsvc_dissect_NetCharDevQPurgeSelf_request, srvsvc_dissect_NetCharDevQPurgeSelf_response},
	{ 8, "NetConnEnum",
	   srvsvc_dissect_NetConnEnum_request, srvsvc_dissect_NetConnEnum_response},
	{ 9, "NetFileEnum",
	   srvsvc_dissect_NetFileEnum_request, srvsvc_dissect_NetFileEnum_response},
	{ 10, "NetFileGetInfo",
	   srvsvc_dissect_NetFileGetInfo_request, srvsvc_dissect_NetFileGetInfo_response},
	{ 11, "NetFileClose",
	   srvsvc_dissect_NetFileClose_request, srvsvc_dissect_NetFileClose_response},
	{ 12, "NetSessEnum",
	   srvsvc_dissect_NetSessEnum_request, srvsvc_dissect_NetSessEnum_response},
	{ 13, "NetSessDel",
	   srvsvc_dissect_NetSessDel_request, srvsvc_dissect_NetSessDel_response},
	{ 14, "NetShareAdd",
	   srvsvc_dissect_NetShareAdd_request, srvsvc_dissect_NetShareAdd_response},
	{ 15, "NetShareEnumAll",
	   srvsvc_dissect_NetShareEnumAll_request, srvsvc_dissect_NetShareEnumAll_response},
	{ 16, "NetShareGetInfo",
	   srvsvc_dissect_NetShareGetInfo_request, srvsvc_dissect_NetShareGetInfo_response},
	{ 17, "NetShareSetInfo",
	   srvsvc_dissect_NetShareSetInfo_request, srvsvc_dissect_NetShareSetInfo_response},
	{ 18, "NetShareDel",
	   srvsvc_dissect_NetShareDel_request, srvsvc_dissect_NetShareDel_response},
	{ 19, "NetShareDelSticky",
	   srvsvc_dissect_NetShareDelSticky_request, srvsvc_dissect_NetShareDelSticky_response},
	{ 20, "NetShareCheck",
	   srvsvc_dissect_NetShareCheck_request, srvsvc_dissect_NetShareCheck_response},
	{ 21, "NetSrvGetInfo",
	   srvsvc_dissect_NetSrvGetInfo_request, srvsvc_dissect_NetSrvGetInfo_response},
	{ 22, "NetSrvSetInfo",
	   srvsvc_dissect_NetSrvSetInfo_request, srvsvc_dissect_NetSrvSetInfo_response},
	{ 23, "NetDiskEnum",
	   srvsvc_dissect_NetDiskEnum_request, srvsvc_dissect_NetDiskEnum_response},
	{ 24, "NetServerStatisticsGet",
	   srvsvc_dissect_NetServerStatisticsGet_request, srvsvc_dissect_NetServerStatisticsGet_response},
	{ 25, "NetTransportAdd",
	   srvsvc_dissect_NetTransportAdd_request, srvsvc_dissect_NetTransportAdd_response},
	{ 26, "NetTransportEnum",
	   srvsvc_dissect_NetTransportEnum_request, srvsvc_dissect_NetTransportEnum_response},
	{ 27, "NetTransportDel",
	   srvsvc_dissect_NetTransportDel_request, srvsvc_dissect_NetTransportDel_response},
	{ 28, "NetRemoteTOD",
	   srvsvc_dissect_NetRemoteTOD_request, srvsvc_dissect_NetRemoteTOD_response},
	{ 29, "NetSetServiceBits",
	   srvsvc_dissect_NetSetServiceBits_request, srvsvc_dissect_NetSetServiceBits_response},
	{ 30, "NetPathType",
	   srvsvc_dissect_NetPathType_request, srvsvc_dissect_NetPathType_response},
	{ 31, "NetPathCanonicalize",
	   srvsvc_dissect_NetPathCanonicalize_request, srvsvc_dissect_NetPathCanonicalize_response},
	{ 32, "NetPathCompare",
	   srvsvc_dissect_NetPathCompare_request, srvsvc_dissect_NetPathCompare_response},
	{ 33, "NetNameValidate",
	   srvsvc_dissect_NetNameValidate_request, srvsvc_dissect_NetNameValidate_response},
	{ 34, "NETRPRNAMECANONICALIZE",
	   srvsvc_dissect_NETRPRNAMECANONICALIZE_request, srvsvc_dissect_NETRPRNAMECANONICALIZE_response},
	{ 35, "NetPRNameCompare",
	   srvsvc_dissect_NetPRNameCompare_request, srvsvc_dissect_NetPRNameCompare_response},
	{ 36, "NetShareEnum",
	   srvsvc_dissect_NetShareEnum_request, srvsvc_dissect_NetShareEnum_response},
	{ 37, "NetShareDelStart",
	   srvsvc_dissect_NetShareDelStart_request, srvsvc_dissect_NetShareDelStart_response},
	{ 38, "NetShareDelCommit",
	   srvsvc_dissect_NetShareDelCommit_request, srvsvc_dissect_NetShareDelCommit_response},
	{ 39, "NetGetFileSecurity",
	   srvsvc_dissect_NetGetFileSecurity_request, srvsvc_dissect_NetGetFileSecurity_response},
	{ 40, "NetSetFileSecurity",
	   srvsvc_dissect_NetSetFileSecurity_request, srvsvc_dissect_NetSetFileSecurity_response},
	{ 41, "NetServerTransportAddEx",
	   srvsvc_dissect_NetServerTransportAddEx_request, srvsvc_dissect_NetServerTransportAddEx_response},
	{ 42, "NetServerSetServiceBitsEx",
	   srvsvc_dissect_NetServerSetServiceBitsEx_request, srvsvc_dissect_NetServerSetServiceBitsEx_response},
	{ 43, "NETRDFSGETVERSION",
	   srvsvc_dissect_NETRDFSGETVERSION_request, srvsvc_dissect_NETRDFSGETVERSION_response},
	{ 44, "NETRDFSCREATELOCALPARTITION",
	   srvsvc_dissect_NETRDFSCREATELOCALPARTITION_request, srvsvc_dissect_NETRDFSCREATELOCALPARTITION_response},
	{ 45, "NETRDFSDELETELOCALPARTITION",
	   srvsvc_dissect_NETRDFSDELETELOCALPARTITION_request, srvsvc_dissect_NETRDFSDELETELOCALPARTITION_response},
	{ 46, "NETRDFSSETLOCALVOLUMESTATE",
	   srvsvc_dissect_NETRDFSSETLOCALVOLUMESTATE_request, srvsvc_dissect_NETRDFSSETLOCALVOLUMESTATE_response},
	{ 47, "NETRDFSSETSERVERINFO",
	   srvsvc_dissect_NETRDFSSETSERVERINFO_request, srvsvc_dissect_NETRDFSSETSERVERINFO_response},
	{ 48, "NETRDFSCREATEEXITPOINT",
	   srvsvc_dissect_NETRDFSCREATEEXITPOINT_request, srvsvc_dissect_NETRDFSCREATEEXITPOINT_response},
	{ 49, "NETRDFSDELETEEXITPOINT",
	   srvsvc_dissect_NETRDFSDELETEEXITPOINT_request, srvsvc_dissect_NETRDFSDELETEEXITPOINT_response},
	{ 50, "NETRDFSMODIFYPREFIX",
	   srvsvc_dissect_NETRDFSMODIFYPREFIX_request, srvsvc_dissect_NETRDFSMODIFYPREFIX_response},
	{ 51, "NETRDFSFIXLOCALVOLUME",
	   srvsvc_dissect_NETRDFSFIXLOCALVOLUME_request, srvsvc_dissect_NETRDFSFIXLOCALVOLUME_response},
	{ 52, "NETRDFSMANAGERREPORTSITEINFO",
	   srvsvc_dissect_NETRDFSMANAGERREPORTSITEINFO_request, srvsvc_dissect_NETRDFSMANAGERREPORTSITEINFO_response},
	{ 53, "NETRSERVERTRANSPORTDELEX",
	   srvsvc_dissect_NETRSERVERTRANSPORTDELEX_request, srvsvc_dissect_NETRSERVERTRANSPORTDELEX_response},
	{ 0, NULL, NULL, NULL }
};

void proto_register_dcerpc_srvsvc(void)
{
	static hf_register_info hf[] = {
	{ &hf_srvsvc_srvsvc_NetDiskInfo0_disk,
	  { "Disk", "srvsvc.srvsvc_NetDiskInfo0.disk", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetConnInfo1_user,
	  { "User", "srvsvc.srvsvc_NetConnInfo1.user", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_DFSFlags_SHARE_1005_FLAGS_DFS_ROOT,
	  { "Share 1005 Flags Dfs Root", "srvsvc.srvsvc_DFSFlags.SHARE_1005_FLAGS_DFS_ROOT", FT_BOOLEAN, 32, TFS(&srvsvc_DFSFlags_SHARE_1005_FLAGS_DFS_ROOT_tfs), ( 0x00000002 ), NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportCtr1_count,
	  { "Count", "srvsvc.srvsvc_NetTransportCtr1.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1536,
	  { "Info1536", "srvsvc.srvsvc_NetSrvInfo.info1536", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo_info502,
	  { "Info502", "srvsvc.srvsvc_NetShareInfo.info502", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileEnum_resume_handle,
	  { "Resume Handle", "srvsvc.srvsvc_NetFileEnum.resume_handle", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_threadcountadd,
	  { "Threadcountadd", "srvsvc.srvsvc_NetSrvInfo599.threadcountadd", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetRemoteTODInfo_hunds,
	  { "Hunds", "srvsvc.srvsvc_NetRemoteTODInfo.hunds", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareAdd_level,
	  { "Level", "srvsvc.srvsvc_NetShareAdd.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareDelCommit_hnd,
	  { "Hnd", "srvsvc.srvsvc_NetShareDelCommit.hnd", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_networkerrortreshold,
	  { "Networkerrortreshold", "srvsvc.srvsvc_NetSrvInfo599.networkerrortreshold", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetServerTransportAddEx_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetServerTransportAddEx.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_maxkeepcomplsearch,
	  { "Maxkeepcomplsearch", "srvsvc.srvsvc_NetSrvInfo503.maxkeepcomplsearch", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetDiskEnum_maxlen,
	  { "Maxlen", "srvsvc.srvsvc_NetDiskEnum.maxlen", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetRemoteTODInfo_mins,
	  { "Mins", "srvsvc.srvsvc_NetRemoteTODInfo.mins", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_accessalert,
	  { "Accessalert", "srvsvc.srvsvc_NetSrvInfo403.accessalert", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo_info0,
	  { "Info0", "srvsvc.srvsvc_NetTransportInfo.info0", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_initsesstable,
	  { "Initsesstable", "srvsvc.srvsvc_NetSrvInfo599.initsesstable", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessInfo1_num_open,
	  { "Num Open", "srvsvc.srvsvc_NetSessInfo1.num_open", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1509_maxrawbuflen,
	  { "Maxrawbuflen", "srvsvc.srvsvc_NetSrvInfo1509.maxrawbuflen", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_sesssvc,
	  { "Sesssvc", "srvsvc.srvsvc_NetSrvInfo599.sesssvc", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessEnum_level,
	  { "Level", "srvsvc.srvsvc_NetSessEnum.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr_ctr1007,
	  { "Ctr1007", "srvsvc.srvsvc_NetShareCtr.ctr1007", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQCtr1_count,
	  { "Count", "srvsvc.srvsvc_NetCharDevQCtr1.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareSetInfo_share_name,
	  { "Share Name", "srvsvc.srvsvc_NetShareSetInfo.share_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr1501_count,
	  { "Count", "srvsvc.srvsvc_NetShareCtr1501.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo3_vcs,
	  { "Vcs", "srvsvc.srvsvc_NetTransportInfo3.vcs", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_minfreeconnections,
	  { "Minfreeconnections", "srvsvc.srvsvc_NetSrvInfo599.minfreeconnections", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetPRNameCompare_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetPRNameCompare.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_maxfreeconnections,
	  { "Maxfreeconnections", "srvsvc.srvsvc_NetSrvInfo599.maxfreeconnections", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_Statistics_bytessent_low,
	  { "Bytessent Low", "srvsvc.srvsvc_Statistics.bytessent_low", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1529,
	  { "Info1529", "srvsvc.srvsvc_NetSrvInfo.info1529", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_alertsched,
	  { "Alertsched", "srvsvc.srvsvc_NetSrvInfo403.alertsched", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_numfiletasks,
	  { "Numfiletasks", "srvsvc.srvsvc_NetSrvInfo402.numfiletasks", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_diskspacetreshold,
	  { "Diskspacetreshold", "srvsvc.srvsvc_NetSrvInfo599.diskspacetreshold", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo102_announce,
	  { "Announce", "srvsvc.srvsvc_NetSrvInfo102.announce", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_accessalert,
	  { "Accessalert", "srvsvc.srvsvc_NetSrvInfo402.accessalert", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessInfo502_transport,
	  { "Transport", "srvsvc.srvsvc_NetSessInfo502.transport", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareEnum_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetShareEnum.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportCtr1_array,
	  { "Array", "srvsvc.srvsvc_NetTransportCtr1.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo_info1501,
	  { "Info1501", "srvsvc.srvsvc_NetShareInfo.info1501", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo3_name,
	  { "Name", "srvsvc.srvsvc_NetTransportInfo3.name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileClose_fid,
	  { "Fid", "srvsvc.srvsvc_NetFileClose.fid", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_auditedevents,
	  { "Auditedevents", "srvsvc.srvsvc_NetSrvInfo403.auditedevents", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1554_linkinfovalidtime,
	  { "Linkinfovalidtime", "srvsvc.srvsvc_NetSrvInfo1554.linkinfovalidtime", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessInfo2_user_flags,
	  { "User Flags", "srvsvc.srvsvc_NetSessInfo2.user_flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_maxlinkdelay,
	  { "Maxlinkdelay", "srvsvc.srvsvc_NetSrvInfo599.maxlinkdelay", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_eroralert,
	  { "Eroralert", "srvsvc.srvsvc_NetSrvInfo403.eroralert", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessCtr2_count,
	  { "Count", "srvsvc.srvsvc_NetSessCtr2.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1540_enablesharednetdrives,
	  { "Enablesharednetdrives", "srvsvc.srvsvc_NetSrvInfo1540.enablesharednetdrives", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileInfo_info3,
	  { "Info3", "srvsvc.srvsvc_NetFileInfo.info3", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo2_comment,
	  { "Comment", "srvsvc.srvsvc_NetShareInfo2.comment", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_Statistics_start,
	  { "Start", "srvsvc.srvsvc_Statistics.start", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareEnumAll_totalentries,
	  { "Totalentries", "srvsvc.srvsvc_NetShareEnumAll.totalentries", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessInfo502_user,
	  { "User", "srvsvc.srvsvc_NetSessInfo502.user", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportEnum_level,
	  { "Level", "srvsvc.srvsvc_NetTransportEnum.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_numfiletasks,
	  { "Numfiletasks", "srvsvc.srvsvc_NetSrvInfo403.numfiletasks", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQGetInfo_queue_name,
	  { "Queue Name", "srvsvc.srvsvc_NetCharDevQGetInfo.queue_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_sessconns,
	  { "Sessconns", "srvsvc.srvsvc_NetSrvInfo599.sessconns", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_sesssvc,
	  { "Sesssvc", "srvsvc.srvsvc_NetSrvInfo503.sesssvc", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevInfo_info1,
	  { "Info1", "srvsvc.srvsvc_NetCharDevInfo.info1", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetGetFileSecurity_sd_buf,
	  { "Sd Buf", "srvsvc.srvsvc_NetGetFileSecurity.sd_buf", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetConnInfo0_conn_id,
	  { "Conn Id", "srvsvc.srvsvc_NetConnInfo0.conn_id", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_maxmpxct,
	  { "Maxmpxct", "srvsvc.srvsvc_NetSrvInfo599.maxmpxct", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileEnum_ctr,
	  { "Ctr", "srvsvc.srvsvc_NetFileEnum.ctr", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo502_sessconns,
	  { "Sessconns", "srvsvc.srvsvc_NetSrvInfo502.sessconns", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_rawworkitems,
	  { "Rawworkitems", "srvsvc.srvsvc_NetSrvInfo599.rawworkitems", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareEnumAll_max_buffer,
	  { "Max Buffer", "srvsvc.srvsvc_NetShareEnumAll.max_buffer", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_minrcvqueue,
	  { "Minrcvqueue", "srvsvc.srvsvc_NetSrvInfo503.minrcvqueue", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo_info1,
	  { "Info1", "srvsvc.srvsvc_NetTransportInfo.info1", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_threadcountadd,
	  { "Threadcountadd", "srvsvc.srvsvc_NetSrvInfo503.threadcountadd", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileInfo3_user,
	  { "User", "srvsvc.srvsvc_NetFileInfo3.user", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetRemoteTODInfo_weekday,
	  { "Weekday", "srvsvc.srvsvc_NetRemoteTODInfo.weekday", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo3_addr_len,
	  { "Addr Len", "srvsvc.srvsvc_NetTransportInfo3.addr_len", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_Statistics_bytesrcvd_low,
	  { "Bytesrcvd Low", "srvsvc.srvsvc_Statistics.bytesrcvd_low", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1549_networkerrortreshold,
	  { "Networkerrortreshold", "srvsvc.srvsvc_NetSrvInfo1549.networkerrortreshold", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetServerSetServiceBitsEx_servicebitsofinterest,
	  { "Servicebitsofinterest", "srvsvc.srvsvc_NetServerSetServiceBitsEx.servicebitsofinterest", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportEnum_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetTransportEnum.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1542_maxfreeconnections,
	  { "Maxfreeconnections", "srvsvc.srvsvc_NetSrvInfo1542.maxfreeconnections", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_enableoplockforceclose,
	  { "Enableoplockforceclose", "srvsvc.srvsvc_NetSrvInfo599.enableoplockforceclose", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvGetInfo_info,
	  { "Info", "srvsvc.srvsvc_NetSrvGetInfo.info", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetNameValidate_name,
	  { "Name", "srvsvc.srvsvc_NetNameValidate.name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1511,
	  { "Info1511", "srvsvc.srvsvc_NetSrvInfo.info1511", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr_ctr501,
	  { "Ctr501", "srvsvc.srvsvc_NetShareCtr.ctr501", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo0_addr,
	  { "Addr", "srvsvc.srvsvc_NetTransportInfo0.addr", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_opensearch,
	  { "Opensearch", "srvsvc.srvsvc_NetSrvInfo599.opensearch", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileCtr3_array,
	  { "Array", "srvsvc.srvsvc_NetFileCtr3.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessCtr_ctr0,
	  { "Ctr0", "srvsvc.srvsvc_NetSessCtr.ctr0", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1552_maxlinkdelay,
	  { "Maxlinkdelay", "srvsvc.srvsvc_NetSrvInfo1552.maxlinkdelay", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_maxkeepcomplsearch,
	  { "Maxkeepcomplsearch", "srvsvc.srvsvc_NetSrvInfo599.maxkeepcomplsearch", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_enablefcbopens,
	  { "Enablefcbopens", "srvsvc.srvsvc_NetSrvInfo503.enablefcbopens", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo102_version_minor,
	  { "Version Minor", "srvsvc.srvsvc_NetSrvInfo102.version_minor", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1501,
	  { "Info1501", "srvsvc.srvsvc_NetSrvInfo.info1501", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetDiskEnum_totalentries,
	  { "Totalentries", "srvsvc.srvsvc_NetDiskEnum.totalentries", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1107,
	  { "Info1107", "srvsvc.srvsvc_NetSrvInfo.info1107", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1520,
	  { "Info1520", "srvsvc.srvsvc_NetSrvInfo.info1520", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevInfo_info0,
	  { "Info0", "srvsvc.srvsvc_NetCharDevInfo.info0", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo1006_max_users,
	  { "Max Users", "srvsvc.srvsvc_NetShareInfo1006.max_users", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_openfiles,
	  { "Openfiles", "srvsvc.srvsvc_NetSrvInfo402.openfiles", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQEnum_level,
	  { "Level", "srvsvc.srvsvc_NetCharDevQEnum.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo502_rawworkitems,
	  { "Rawworkitems", "srvsvc.srvsvc_NetSrvInfo502.rawworkitems", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_oplockbreakresponsewait,
	  { "Oplockbreakresponsewait", "srvsvc.srvsvc_NetSrvInfo599.oplockbreakresponsewait", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQEnum_totalentries,
	  { "Totalentries", "srvsvc.srvsvc_NetCharDevQEnum.totalentries", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo3_password,
	  { "Password", "srvsvc.srvsvc_NetTransportInfo3.password", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info502,
	  { "Info502", "srvsvc.srvsvc_NetSrvInfo.info502", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_initworkitems,
	  { "Initworkitems", "srvsvc.srvsvc_NetSrvInfo503.initworkitems", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportAdd_level,
	  { "Level", "srvsvc.srvsvc_NetTransportAdd.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo502_timesource,
	  { "Timesource", "srvsvc.srvsvc_NetSrvInfo502.timesource", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileEnum_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetFileEnum.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSetServiceBits_updateimmediately,
	  { "Updateimmediately", "srvsvc.srvsvc_NetSetServiceBits.updateimmediately", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1537,
	  { "Info1537", "srvsvc.srvsvc_NetSrvInfo.info1537", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1534,
	  { "Info1534", "srvsvc.srvsvc_NetSrvInfo.info1534", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1525_maxkeepcomplsearch,
	  { "Maxkeepcomplsearch", "srvsvc.srvsvc_NetSrvInfo1525.maxkeepcomplsearch", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileCtr3_count,
	  { "Count", "srvsvc.srvsvc_NetFileCtr3.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCheck_device_name,
	  { "Device Name", "srvsvc.srvsvc_NetShareCheck.device_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileEnum_totalentries,
	  { "Totalentries", "srvsvc.srvsvc_NetFileEnum.totalentries", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1528,
	  { "Info1528", "srvsvc.srvsvc_NetSrvInfo.info1528", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_scavtimeout,
	  { "Scavtimeout", "srvsvc.srvsvc_NetSrvInfo503.scavtimeout", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_guestaccount,
	  { "Guestaccount", "srvsvc.srvsvc_NetSrvInfo402.guestaccount", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareEnum_resume_handle,
	  { "Resume Handle", "srvsvc.srvsvc_NetShareEnum.resume_handle", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1538_enablefcbopens,
	  { "Enablefcbopens", "srvsvc.srvsvc_NetSrvInfo1538.enablefcbopens", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_alist_mtime,
	  { "Alist Mtime", "srvsvc.srvsvc_NetSrvInfo402.alist_mtime", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportCtr0_count,
	  { "Count", "srvsvc.srvsvc_NetTransportCtr0.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_alertsched,
	  { "Alertsched", "srvsvc.srvsvc_NetSrvInfo402.alertsched", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileEnum_level,
	  { "Level", "srvsvc.srvsvc_NetFileEnum.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1529_minrcvqueue,
	  { "Minrcvqueue", "srvsvc.srvsvc_NetSrvInfo1529.minrcvqueue", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo3_transport_flags,
	  { "Transport Flags", "srvsvc.srvsvc_NetTransportInfo3.transport_flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_erroralert,
	  { "Erroralert", "srvsvc.srvsvc_NetSrvInfo402.erroralert", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetConnInfo1_share,
	  { "Share", "srvsvc.srvsvc_NetConnInfo1.share", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info599,
	  { "Info599", "srvsvc.srvsvc_NetSrvInfo.info599", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_maxcopywritelen,
	  { "Maxcopywritelen", "srvsvc.srvsvc_NetSrvInfo503.maxcopywritelen", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareSetInfo_info,
	  { "Info", "srvsvc.srvsvc_NetShareSetInfo.info", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessInfo502_num_open,
	  { "Num Open", "srvsvc.srvsvc_NetSessInfo502.num_open", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetGetFileSecurity_share,
	  { "Share", "srvsvc.srvsvc_NetGetFileSecurity.share", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_enablesharednetdrives,
	  { "Enablesharednetdrives", "srvsvc.srvsvc_NetSrvInfo503.enablesharednetdrives", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_maxcopyreadlen,
	  { "Maxcopyreadlen", "srvsvc.srvsvc_NetSrvInfo503.maxcopyreadlen", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1509,
	  { "Info1509", "srvsvc.srvsvc_NetSrvInfo.info1509", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessInfo1_client,
	  { "Client", "srvsvc.srvsvc_NetSessInfo1.client", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1540,
	  { "Info1540", "srvsvc.srvsvc_NetSrvInfo.info1540", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo1005_dfs_flags,
	  { "Dfs Flags", "srvsvc.srvsvc_NetShareInfo1005.dfs_flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_sessusers,
	  { "Sessusers", "srvsvc.srvsvc_NetSrvInfo599.sessusers", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevInfo0_device,
	  { "Device", "srvsvc.srvsvc_NetCharDevInfo0.device", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo502_sd,
	  { "Sd", "srvsvc.srvsvc_NetShareInfo502.sd", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo3_domain,
	  { "Domain", "srvsvc.srvsvc_NetTransportInfo3.domain", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_chdevjobs,
	  { "Chdevjobs", "srvsvc.srvsvc_NetSrvInfo403.chdevjobs", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_threadpriority,
	  { "Threadpriority", "srvsvc.srvsvc_NetSrvInfo599.threadpriority", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevCtr1_count,
	  { "Count", "srvsvc.srvsvc_NetCharDevCtr1.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1017_announce,
	  { "Announce", "srvsvc.srvsvc_NetSrvInfo1017.announce", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_maxpagedmemoryusage,
	  { "Maxpagedmemoryusage", "srvsvc.srvsvc_NetSrvInfo599.maxpagedmemoryusage", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_guestaccount,
	  { "Guestaccount", "srvsvc.srvsvc_NetSrvInfo403.guestaccount", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessInfo502_client,
	  { "Client", "srvsvc.srvsvc_NetSessInfo502.client", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareDel_share_name,
	  { "Share Name", "srvsvc.srvsvc_NetShareDel.share_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_maxmpxct,
	  { "Maxmpxct", "srvsvc.srvsvc_NetSrvInfo503.maxmpxct", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevCtr0_array,
	  { "Array", "srvsvc.srvsvc_NetCharDevCtr0.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_alerts,
	  { "Alerts", "srvsvc.srvsvc_NetSrvInfo402.alerts", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_maxpagedmemoryusage,
	  { "Maxpagedmemoryusage", "srvsvc.srvsvc_NetSrvInfo503.maxpagedmemoryusage", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo101_comment,
	  { "Comment", "srvsvc.srvsvc_NetSrvInfo101.comment", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1556_maxworkitemidletime,
	  { "Maxworkitemidletime", "srvsvc.srvsvc_NetSrvInfo1556.maxworkitemidletime", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareDelStart_hnd,
	  { "Hnd", "srvsvc.srvsvc_NetShareDelStart.hnd", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info403,
	  { "Info403", "srvsvc.srvsvc_NetSrvInfo.info403", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo501_csc_policy,
	  { "Csc Policy", "srvsvc.srvsvc_NetShareInfo501.csc_policy", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo1_addr_len,
	  { "Addr Len", "srvsvc.srvsvc_NetTransportInfo1.addr_len", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSetServiceBits_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetSetServiceBits.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_srvheuristics,
	  { "Srvheuristics", "srvsvc.srvsvc_NetSrvInfo402.srvheuristics", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo102_version_major,
	  { "Version Major", "srvsvc.srvsvc_NetSrvInfo102.version_major", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr_ctr1004,
	  { "Ctr1004", "srvsvc.srvsvc_NetShareCtr.ctr1004", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1510,
	  { "Info1510", "srvsvc.srvsvc_NetSrvInfo.info1510", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileInfo_info2,
	  { "Info2", "srvsvc.srvsvc_NetFileInfo.info2", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvGetInfo_level,
	  { "Level", "srvsvc.srvsvc_NetSrvGetInfo.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareDelSticky_share_name,
	  { "Share Name", "srvsvc.srvsvc_NetShareDelSticky.share_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetConnEnum_totalentries,
	  { "Totalentries", "srvsvc.srvsvc_NetConnEnum.totalentries", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_TransportFlags_SVTI2_REMAP_PIPE_NAMES,
	  { "Svti2 Remap Pipe Names", "srvsvc.srvsvc_TransportFlags.SVTI2_REMAP_PIPE_NAMES", FT_BOOLEAN, 32, TFS(&srvsvc_TransportFlags_SVTI2_REMAP_PIPE_NAMES_tfs), ( 0x00000001 ), NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr501_count,
	  { "Count", "srvsvc.srvsvc_NetShareCtr501.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_enableoplockforceclose,
	  { "Enableoplockforceclose", "srvsvc.srvsvc_NetSrvInfo503.enableoplockforceclose", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo2_vcs,
	  { "Vcs", "srvsvc.srvsvc_NetTransportInfo2.vcs", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo502_lmannounce,
	  { "Lmannounce", "srvsvc.srvsvc_NetSrvInfo502.lmannounce", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo502_irpstacksize,
	  { "Irpstacksize", "srvsvc.srvsvc_NetSrvInfo502.irpstacksize", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1018_anndelta,
	  { "Anndelta", "srvsvc.srvsvc_NetSrvInfo1018.anndelta", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_diskalert,
	  { "Diskalert", "srvsvc.srvsvc_NetSrvInfo402.diskalert", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileGetInfo_fid,
	  { "Fid", "srvsvc.srvsvc_NetFileGetInfo.fid", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1544_initconntable,
	  { "Initconntable", "srvsvc.srvsvc_NetSrvInfo1544.initconntable", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportAdd_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetTransportAdd.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareDelStart_reserved,
	  { "Reserved", "srvsvc.srvsvc_NetShareDelStart.reserved", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetNameValidate_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetNameValidate.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQCtr1_array,
	  { "Array", "srvsvc.srvsvc_NetCharDevQCtr1.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo501_type,
	  { "Type", "srvsvc.srvsvc_NetShareInfo501.type", FT_UINT32, BASE_DEC, VALS(srvsvc_srvsvc_ShareType_vals), 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr1_array,
	  { "Array", "srvsvc.srvsvc_NetShareCtr1.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetConnEnum_max_buffer,
	  { "Max Buffer", "srvsvc.srvsvc_NetConnEnum.max_buffer", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_minfreeworkitems,
	  { "Minfreeworkitems", "srvsvc.srvsvc_NetSrvInfo599.minfreeworkitems", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo502_initworkitems,
	  { "Initworkitems", "srvsvc.srvsvc_NetSrvInfo502.initworkitems", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetGetFileSecurity_securityinformation,
	  { "Securityinformation", "srvsvc.srvsvc_NetGetFileSecurity.securityinformation", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetConnEnum_level,
	  { "Level", "srvsvc.srvsvc_NetConnEnum.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo2_permissions,
	  { "Permissions", "srvsvc.srvsvc_NetShareInfo2.permissions", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1555_scavqosinfoupdatetime,
	  { "Scavqosinfoupdatetime", "srvsvc.srvsvc_NetSrvInfo1555.scavqosinfoupdatetime", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_minfreeconnections,
	  { "Minfreeconnections", "srvsvc.srvsvc_NetSrvInfo503.minfreeconnections", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetRemoteTODInfo_elapsed,
	  { "Elapsed", "srvsvc.srvsvc_NetRemoteTODInfo.elapsed", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_maxaudits,
	  { "Maxaudits", "srvsvc.srvsvc_NetSrvInfo402.maxaudits", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_timesource,
	  { "Timesource", "srvsvc.srvsvc_NetSrvInfo503.timesource", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessDel_client,
	  { "Client", "srvsvc.srvsvc_NetSessDel.client", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_chdevjobs,
	  { "Chdevjobs", "srvsvc.srvsvc_NetSrvInfo402.chdevjobs", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo0_name,
	  { "Name", "srvsvc.srvsvc_NetTransportInfo0.name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQSetInfo_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetCharDevQSetInfo.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1534_oplockbreakwait,
	  { "Oplockbreakwait", "srvsvc.srvsvc_NetSrvInfo1534.oplockbreakwait", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo_info0,
	  { "Info0", "srvsvc.srvsvc_NetShareInfo.info0", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetRemoteTODInfo_secs,
	  { "Secs", "srvsvc.srvsvc_NetRemoteTODInfo.secs", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo1007_flags,
	  { "Flags", "srvsvc.srvsvc_NetShareInfo1007.flags", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_minkeepcomplsearch,
	  { "Minkeepcomplsearch", "srvsvc.srvsvc_NetSrvInfo503.minkeepcomplsearch", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQEnum_user,
	  { "User", "srvsvc.srvsvc_NetCharDevQEnum.user", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQInfo1_priority,
	  { "Priority", "srvsvc.srvsvc_NetCharDevQInfo1.priority", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo0_name,
	  { "Name", "srvsvc.srvsvc_NetShareInfo0.name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportCtr2_count,
	  { "Count", "srvsvc.srvsvc_NetTransportCtr2.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetRemoteTOD_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetRemoteTOD.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo0_addr_len,
	  { "Addr Len", "srvsvc.srvsvc_NetTransportInfo0.addr_len", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_maxcopyreadlen,
	  { "Maxcopyreadlen", "srvsvc.srvsvc_NetSrvInfo599.maxcopyreadlen", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQInfo0_device,
	  { "Device", "srvsvc.srvsvc_NetCharDevQInfo0.device", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo502_sesssvc,
	  { "Sesssvc", "srvsvc.srvsvc_NetSrvInfo502.sesssvc", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_DFSFlags_CSC_CACHE_VDO,
	  { "Csc Cache Vdo", "srvsvc.srvsvc_DFSFlags.CSC_CACHE_VDO", FT_BOOLEAN, 32, TFS(&srvsvc_DFSFlags_CSC_CACHE_VDO_tfs), ( 0x00000020 ), NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr1501_array,
	  { "Array", "srvsvc.srvsvc_NetShareCtr1501.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareSetInfo_parm_error,
	  { "Parm Error", "srvsvc.srvsvc_NetShareSetInfo.parm_error", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareEnumAll_ctr,
	  { "Ctr", "srvsvc.srvsvc_NetShareEnumAll.ctr", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo102_platform_id,
	  { "Platform Id", "srvsvc.srvsvc_NetSrvInfo102.platform_id", FT_UINT32, BASE_DEC, VALS(srvsvc_srvsvc_PlatformId_vals), 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessCtr_ctr10,
	  { "Ctr10", "srvsvc.srvsvc_NetSessCtr.ctr10", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo101_version_minor,
	  { "Version Minor", "srvsvc.srvsvc_NetSrvInfo101.version_minor", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQSetInfo_parm_error,
	  { "Parm Error", "srvsvc.srvsvc_NetCharDevQSetInfo.parm_error", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1550_diskspacetreshold,
	  { "Diskspacetreshold", "srvsvc.srvsvc_NetSrvInfo1550.diskspacetreshold", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_enableoplocks,
	  { "Enableoplocks", "srvsvc.srvsvc_NetSrvInfo599.enableoplocks", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr501_array,
	  { "Array", "srvsvc.srvsvc_NetShareCtr501.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareDel_reserved,
	  { "Reserved", "srvsvc.srvsvc_NetShareDel.reserved", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_acceptdownlevelapis,
	  { "Acceptdownlevelapis", "srvsvc.srvsvc_NetSrvInfo599.acceptdownlevelapis", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_security,
	  { "Security", "srvsvc.srvsvc_NetSrvInfo402.security", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetConnInfo1_conn_id,
	  { "Conn Id", "srvsvc.srvsvc_NetConnInfo1.conn_id", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessInfo502_user_flags,
	  { "User Flags", "srvsvc.srvsvc_NetSessInfo502.user_flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1502,
	  { "Info1502", "srvsvc.srvsvc_NetSrvInfo.info1502", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1541_minfreeconnections,
	  { "Minfreeconnections", "srvsvc.srvsvc_NetSrvInfo1541.minfreeconnections", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_linkinfovalidtime,
	  { "Linkinfovalidtime", "srvsvc.srvsvc_NetSrvInfo599.linkinfovalidtime", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_sessreqs,
	  { "Sessreqs", "srvsvc.srvsvc_NetSrvInfo403.sessreqs", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareAdd_parm_error,
	  { "Parm Error", "srvsvc.srvsvc_NetShareAdd.parm_error", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info100,
	  { "Info100", "srvsvc.srvsvc_NetSrvInfo.info100", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr502_count,
	  { "Count", "srvsvc.srvsvc_NetShareCtr502.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1514_enablesoftcompat,
	  { "Enablesoftcompat", "srvsvc.srvsvc_NetSrvInfo1514.enablesoftcompat", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_minlinkthroughput,
	  { "Minlinkthroughput", "srvsvc.srvsvc_NetSrvInfo599.minlinkthroughput", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_SessionUserFlags_SESS_NOENCRYPTION,
	  { "Sess Noencryption", "srvsvc.srvsvc_SessionUserFlags.SESS_NOENCRYPTION", FT_BOOLEAN, 32, TFS(&srvsvc_SessionUserFlags_SESS_NOENCRYPTION_tfs), ( 0x00000002 ), NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetServerSetServiceBitsEx_updateimmediately,
	  { "Updateimmediately", "srvsvc.srvsvc_NetServerSetServiceBitsEx.updateimmediately", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetConnInfo1_conn_time,
	  { "Conn Time", "srvsvc.srvsvc_NetConnInfo1.conn_time", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1543_initsesstable,
	  { "Initsesstable", "srvsvc.srvsvc_NetSrvInfo1543.initsesstable", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_xactmemsize,
	  { "Xactmemsize", "srvsvc.srvsvc_NetSrvInfo503.xactmemsize", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevGetInfo_level,
	  { "Level", "srvsvc.srvsvc_NetCharDevGetInfo.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_DFSFlags_FLAGS_FORCE_SHARED_DELETE,
	  { "Flags Force Shared Delete", "srvsvc.srvsvc_DFSFlags.FLAGS_FORCE_SHARED_DELETE", FT_BOOLEAN, 32, TFS(&srvsvc_DFSFlags_FLAGS_FORCE_SHARED_DELETE_tfs), ( 0x00000200 ), NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_Statistics_stimeouts,
	  { "Stimeouts", "srvsvc.srvsvc_Statistics.stimeouts", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_sessopen,
	  { "Sessopen", "srvsvc.srvsvc_NetSrvInfo599.sessopen", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_Statistics_bytessent_high,
	  { "Bytessent High", "srvsvc.srvsvc_Statistics.bytessent_high", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo1_domain,
	  { "Domain", "srvsvc.srvsvc_NetTransportInfo1.domain", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo1007_alternate_directory_name,
	  { "Alternate Directory Name", "srvsvc.srvsvc_NetShareInfo1007.alternate_directory_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetConnCtr0_count,
	  { "Count", "srvsvc.srvsvc_NetConnCtr0.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_minkeepsearch,
	  { "Minkeepsearch", "srvsvc.srvsvc_NetSrvInfo503.minkeepsearch", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_acceptdownlevelapis,
	  { "Acceptdownlevelapis", "srvsvc.srvsvc_NetSrvInfo503.acceptdownlevelapis", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr2_array,
	  { "Array", "srvsvc.srvsvc_NetShareCtr2.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetGetFileSecurity_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetGetFileSecurity.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo502_maxpagedmemoryusage,
	  { "Maxpagedmemoryusage", "srvsvc.srvsvc_NetSrvInfo502.maxpagedmemoryusage", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessInfo10_client,
	  { "Client", "srvsvc.srvsvc_NetSessInfo10.client", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportCtr_ctr0,
	  { "Ctr0", "srvsvc.srvsvc_NetTransportCtr.ctr0", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQPurge_queue_name,
	  { "Queue Name", "srvsvc.srvsvc_NetCharDevQPurge.queue_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_Statistics_jobsqueued,
	  { "Jobsqueued", "srvsvc.srvsvc_Statistics.jobsqueued", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1550,
	  { "Info1550", "srvsvc.srvsvc_NetSrvInfo.info1550", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo_info1007,
	  { "Info1007", "srvsvc.srvsvc_NetShareInfo.info1007", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQGetInfo_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetCharDevQGetInfo.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1513,
	  { "Info1513", "srvsvc.srvsvc_NetSrvInfo.info1513", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSetFileSecurity_file,
	  { "File", "srvsvc.srvsvc_NetSetFileSecurity.file", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_activelocks,
	  { "Activelocks", "srvsvc.srvsvc_NetSrvInfo402.activelocks", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo2_addr,
	  { "Addr", "srvsvc.srvsvc_NetTransportInfo2.addr", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo102_anndelta,
	  { "Anndelta", "srvsvc.srvsvc_NetSrvInfo102.anndelta", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileGetInfo_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetFileGetInfo.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_threadpriority,
	  { "Threadpriority", "srvsvc.srvsvc_NetSrvInfo503.threadpriority", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessInfo502_idle_time,
	  { "Idle Time", "srvsvc.srvsvc_NetSessInfo502.idle_time", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1537_enableoplockforceclose,
	  { "Enableoplockforceclose", "srvsvc.srvsvc_NetSrvInfo1537.enableoplockforceclose", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_maxnonpagedmemoryusage,
	  { "Maxnonpagedmemoryusage", "srvsvc.srvsvc_NetSrvInfo503.maxnonpagedmemoryusage", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_opensearch,
	  { "Opensearch", "srvsvc.srvsvc_NetSrvInfo503.opensearch", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_enableforcedlogoff,
	  { "Enableforcedlogoff", "srvsvc.srvsvc_NetSrvInfo599.enableforcedlogoff", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvSetInfo_parm_error,
	  { "Parm Error", "srvsvc.srvsvc_NetSrvSetInfo.parm_error", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareEnumAll_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetShareEnumAll.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_glist_mtime,
	  { "Glist Mtime", "srvsvc.srvsvc_NetSrvInfo403.glist_mtime", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo502_comment,
	  { "Comment", "srvsvc.srvsvc_NetShareInfo502.comment", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1552,
	  { "Info1552", "srvsvc.srvsvc_NetSrvInfo.info1552", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr1004_count,
	  { "Count", "srvsvc.srvsvc_NetShareCtr1004.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_minkeepcomplsearch,
	  { "Minkeepcomplsearch", "srvsvc.srvsvc_NetSrvInfo599.minkeepcomplsearch", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetConnInfo1_conn_type,
	  { "Conn Type", "srvsvc.srvsvc_NetConnInfo1.conn_type", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetRemoteTODInfo_year,
	  { "Year", "srvsvc.srvsvc_NetRemoteTODInfo.year", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportCtr_ctr1,
	  { "Ctr1", "srvsvc.srvsvc_NetTransportCtr.ctr1", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileInfo2_fid,
	  { "Fid", "srvsvc.srvsvc_NetFileInfo2.fid", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevInfo1_time,
	  { "Time", "srvsvc.srvsvc_NetCharDevInfo1.time", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareEnum_ctr,
	  { "Ctr", "srvsvc.srvsvc_NetShareEnum.ctr", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetPathCanonicalize_prefix,
	  { "Prefix", "srvsvc.srvsvc_NetPathCanonicalize.prefix", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_Statistics_syserrors,
	  { "Syserrors", "srvsvc.srvsvc_Statistics.syserrors", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr_ctr0,
	  { "Ctr0", "srvsvc.srvsvc_NetShareCtr.ctr0", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetPathCanonicalize_path,
	  { "Path", "srvsvc.srvsvc_NetPathCanonicalize.path", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQSetInfo_level,
	  { "Level", "srvsvc.srvsvc_NetCharDevQSetInfo.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQInfo1_device,
	  { "Device", "srvsvc.srvsvc_NetCharDevQInfo1.device", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSetServiceBits_servicebits,
	  { "Servicebits", "srvsvc.srvsvc_NetSetServiceBits.servicebits", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1522_minkeepsearch,
	  { "Minkeepsearch", "srvsvc.srvsvc_NetSrvInfo1522.minkeepsearch", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessInfo1_idle_time,
	  { "Idle Time", "srvsvc.srvsvc_NetSessInfo1.idle_time", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetPathCanonicalize_pathflags,
	  { "Pathflags", "srvsvc.srvsvc_NetPathCanonicalize.pathflags", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_logonalert,
	  { "Logonalert", "srvsvc.srvsvc_NetSrvInfo402.logonalert", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareGetInfo_info,
	  { "Info", "srvsvc.srvsvc_NetShareGetInfo.info", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetDiskEnum_level,
	  { "Level", "srvsvc.srvsvc_NetDiskEnum.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_minfreeworkitems,
	  { "Minfreeworkitems", "srvsvc.srvsvc_NetSrvInfo503.minfreeworkitems", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_connections,
	  { "Connections", "srvsvc.srvsvc_NetSrvInfo402.connections", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQCtr_ctr1,
	  { "Ctr1", "srvsvc.srvsvc_NetCharDevQCtr.ctr1", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_maxfreeconnections,
	  { "Maxfreeconnections", "srvsvc.srvsvc_NetSrvInfo503.maxfreeconnections", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_lanmask,
	  { "Lanmask", "srvsvc.srvsvc_NetSrvInfo402.lanmask", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareEnum_totalentries,
	  { "Totalentries", "srvsvc.srvsvc_NetShareEnum.totalentries", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessInfo10_idle_time,
	  { "Idle Time", "srvsvc.srvsvc_NetSessInfo10.idle_time", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSetServiceBits_transport,
	  { "Transport", "srvsvc.srvsvc_NetSetServiceBits.transport", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetServerSetServiceBitsEx_emulated_server_unc,
	  { "Emulated Server Unc", "srvsvc.srvsvc_NetServerSetServiceBitsEx.emulated_server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetRemoteTODInfo_tinterval,
	  { "Tinterval", "srvsvc.srvsvc_NetRemoteTODInfo.tinterval", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1536_enableoplocks,
	  { "Enableoplocks", "srvsvc.srvsvc_NetSrvInfo1536.enableoplocks", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetRemoteTODInfo_hours,
	  { "Hours", "srvsvc.srvsvc_NetRemoteTODInfo.hours", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQInfo1_num_ahead,
	  { "Num Ahead", "srvsvc.srvsvc_NetCharDevQInfo1.num_ahead", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_timesource,
	  { "Timesource", "srvsvc.srvsvc_NetSrvInfo599.timesource", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_domain,
	  { "Domain", "srvsvc.srvsvc_NetSrvInfo599.domain", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_opensearch,
	  { "Opensearch", "srvsvc.srvsvc_NetSrvInfo402.opensearch", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr_ctr1006,
	  { "Ctr1006", "srvsvc.srvsvc_NetShareCtr.ctr1006", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareEnum_level,
	  { "Level", "srvsvc.srvsvc_NetShareEnum.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportEnum_max_buffer,
	  { "Max Buffer", "srvsvc.srvsvc_NetTransportEnum.max_buffer", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareAdd_info,
	  { "Info", "srvsvc.srvsvc_NetShareAdd.info", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportCtr0_array,
	  { "Array", "srvsvc.srvsvc_NetTransportCtr0.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetConnCtr_ctr1,
	  { "Ctr1", "srvsvc.srvsvc_NetConnCtr.ctr1", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQSetInfo_queue_name,
	  { "Queue Name", "srvsvc.srvsvc_NetCharDevQSetInfo.queue_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo100_server_name,
	  { "Server Name", "srvsvc.srvsvc_NetSrvInfo100.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareEnum_max_buffer,
	  { "Max Buffer", "srvsvc.srvsvc_NetShareEnum.max_buffer", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1535,
	  { "Info1535", "srvsvc.srvsvc_NetSrvInfo.info1535", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessInfo1_time,
	  { "Time", "srvsvc.srvsvc_NetSessInfo1.time", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSetFileSecurity_sd_buf,
	  { "Sd Buf", "srvsvc.srvsvc_NetSetFileSecurity.sd_buf", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1521,
	  { "Info1521", "srvsvc.srvsvc_NetSrvInfo.info1521", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareGetInfo_level,
	  { "Level", "srvsvc.srvsvc_NetShareGetInfo.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareEnumAll_level,
	  { "Level", "srvsvc.srvsvc_NetShareEnumAll.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessInfo10_time,
	  { "Time", "srvsvc.srvsvc_NetSessInfo10.time", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr1004_array,
	  { "Array", "srvsvc.srvsvc_NetShareCtr1004.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1502_sessvcs,
	  { "Sessvcs", "srvsvc.srvsvc_NetSrvInfo1502.sessvcs", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_numadmin,
	  { "Numadmin", "srvsvc.srvsvc_NetSrvInfo403.numadmin", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1548_errortreshold,
	  { "Errortreshold", "srvsvc.srvsvc_NetSrvInfo1548.errortreshold", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetDiskInfo_disks,
	  { "Disks", "srvsvc.srvsvc_NetDiskInfo.disks", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessCtr10_array,
	  { "Array", "srvsvc.srvsvc_NetSessCtr10.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_opnum,
	  { "Operation", "srvsvc.opnum", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetConnCtr1_array,
	  { "Array", "srvsvc.srvsvc_NetConnCtr1.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr1006_count,
	  { "Count", "srvsvc.srvsvc_NetShareCtr1006.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCheck_type,
	  { "Type", "srvsvc.srvsvc_NetShareCheck.type", FT_UINT32, BASE_DEC, VALS(srvsvc_srvsvc_ShareType_vals), 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvGetInfo_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetSrvGetInfo.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr0_array,
	  { "Array", "srvsvc.srvsvc_NetShareCtr0.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_diskalert,
	  { "Diskalert", "srvsvc.srvsvc_NetSrvInfo403.diskalert", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo102_server_type,
	  { "Server Type", "srvsvc.srvsvc_NetSrvInfo102.server_type", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1542,
	  { "Info1542", "srvsvc.srvsvc_NetSrvInfo.info1542", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1512,
	  { "Info1512", "srvsvc.srvsvc_NetSrvInfo.info1512", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1503,
	  { "Info1503", "srvsvc.srvsvc_NetSrvInfo.info1503", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessEnum_client,
	  { "Client", "srvsvc.srvsvc_NetSessEnum.client", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr1_count,
	  { "Count", "srvsvc.srvsvc_NetShareCtr1.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetConnCtr0_array,
	  { "Array", "srvsvc.srvsvc_NetConnCtr0.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo2_transport_flags,
	  { "Transport Flags", "srvsvc.srvsvc_NetTransportInfo2.transport_flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr_ctr502,
	  { "Ctr502", "srvsvc.srvsvc_NetShareCtr.ctr502", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_ulist_mtime,
	  { "Ulist Mtime", "srvsvc.srvsvc_NetSrvInfo403.ulist_mtime", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo_info1006,
	  { "Info1006", "srvsvc.srvsvc_NetShareInfo.info1006", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo1_type,
	  { "Type", "srvsvc.srvsvc_NetShareInfo1.type", FT_UINT32, BASE_DEC, VALS(srvsvc_srvsvc_ShareType_vals), 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevEnum_totalentries,
	  { "Totalentries", "srvsvc.srvsvc_NetCharDevEnum.totalentries", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_shares,
	  { "Shares", "srvsvc.srvsvc_NetSrvInfo403.shares", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1016_hidden,
	  { "Hidden", "srvsvc.srvsvc_NetSrvInfo1016.hidden", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessInfo1_user,
	  { "User", "srvsvc.srvsvc_NetSessInfo1.user", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileGetInfo_level,
	  { "Level", "srvsvc.srvsvc_NetFileGetInfo.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1543,
	  { "Info1543", "srvsvc.srvsvc_NetSrvInfo.info1543", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_maxrawbuflen,
	  { "Maxrawbuflen", "srvsvc.srvsvc_NetSrvInfo599.maxrawbuflen", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_opensearch,
	  { "Opensearch", "srvsvc.srvsvc_NetSrvInfo403.opensearch", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetDiskEnum_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetDiskEnum.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQEnum_resume_handle,
	  { "Resume Handle", "srvsvc.srvsvc_NetCharDevQEnum.resume_handle", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessInfo2_client,
	  { "Client", "srvsvc.srvsvc_NetSessInfo2.client", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessCtr2_array,
	  { "Array", "srvsvc.srvsvc_NetSessCtr2.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessDel_user,
	  { "User", "srvsvc.srvsvc_NetSessDel.user", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportCtr3_count,
	  { "Count", "srvsvc.srvsvc_NetTransportCtr3.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvSetInfo_info,
	  { "Info", "srvsvc.srvsvc_NetSrvSetInfo.info", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_Statistics_serrorout,
	  { "Serrorout", "srvsvc.srvsvc_Statistics.serrorout", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1005_comment,
	  { "Comment", "srvsvc.srvsvc_NetSrvInfo1005.comment", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_Statistics_sopens,
	  { "Sopens", "srvsvc.srvsvc_Statistics.sopens", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1544,
	  { "Info1544", "srvsvc.srvsvc_NetSrvInfo.info1544", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1010,
	  { "Info1010", "srvsvc.srvsvc_NetSrvInfo.info1010", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1515,
	  { "Info1515", "srvsvc.srvsvc_NetSrvInfo.info1515", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_numbigbufs,
	  { "Numbigbufs", "srvsvc.srvsvc_NetSrvInfo402.numbigbufs", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo3_addr,
	  { "Addr", "srvsvc.srvsvc_NetTransportInfo3.addr", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1511_sesscons,
	  { "Sesscons", "srvsvc.srvsvc_NetSrvInfo1511.sesscons", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1545_initfiletable,
	  { "Initfiletable", "srvsvc.srvsvc_NetSrvInfo1545.initfiletable", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSetFileSecurity_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetSetFileSecurity.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo502_acceptdownlevelapis,
	  { "Acceptdownlevelapis", "srvsvc.srvsvc_NetSrvInfo502.acceptdownlevelapis", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetGetFileSecurity_file,
	  { "File", "srvsvc.srvsvc_NetGetFileSecurity.file", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_ulist_mtime,
	  { "Ulist Mtime", "srvsvc.srvsvc_NetSrvInfo402.ulist_mtime", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1522,
	  { "Info1522", "srvsvc.srvsvc_NetSrvInfo.info1522", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo101_version_major,
	  { "Version Major", "srvsvc.srvsvc_NetSrvInfo101.version_major", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetNameValidate_name_type,
	  { "Name Type", "srvsvc.srvsvc_NetNameValidate.name_type", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_scavqosinfoupdatetime,
	  { "Scavqosinfoupdatetime", "srvsvc.srvsvc_NetSrvInfo599.scavqosinfoupdatetime", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_enablesoftcompat,
	  { "Enablesoftcompat", "srvsvc.srvsvc_NetSrvInfo599.enablesoftcompat", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_xactmemsize,
	  { "Xactmemsize", "srvsvc.srvsvc_NetSrvInfo599.xactmemsize", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareGetInfo_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetShareGetInfo.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetPRNameCompare_name2,
	  { "Name2", "srvsvc.srvsvc_NetPRNameCompare.name2", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessInfo502_time,
	  { "Time", "srvsvc.srvsvc_NetSessInfo502.time", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_maxrawbuflen,
	  { "Maxrawbuflen", "srvsvc.srvsvc_NetSrvInfo503.maxrawbuflen", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_oplockbreakwait,
	  { "Oplockbreakwait", "srvsvc.srvsvc_NetSrvInfo503.oplockbreakwait", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareDelSticky_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetShareDelSticky.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1524,
	  { "Info1524", "srvsvc.srvsvc_NetSrvInfo.info1524", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_maxaudits,
	  { "Maxaudits", "srvsvc.srvsvc_NetSrvInfo403.maxaudits", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetDiskEnum_info,
	  { "Info", "srvsvc.srvsvc_NetDiskEnum.info", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileCtr_ctr2,
	  { "Ctr2", "srvsvc.srvsvc_NetFileCtr.ctr2", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSetFileSecurity_securityinformation,
	  { "Securityinformation", "srvsvc.srvsvc_NetSetFileSecurity.securityinformation", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo_info2,
	  { "Info2", "srvsvc.srvsvc_NetShareInfo.info2", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1525,
	  { "Info1525", "srvsvc.srvsvc_NetSrvInfo.info1525", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1539_enableraw,
	  { "Enableraw", "srvsvc.srvsvc_NetSrvInfo1539.enableraw", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_alist_mtime,
	  { "Alist Mtime", "srvsvc.srvsvc_NetSrvInfo403.alist_mtime", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1515_enableforcedlogoff,
	  { "Enableforcedlogoff", "srvsvc.srvsvc_NetSrvInfo1515.enableforcedlogoff", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevGetInfo_device_name,
	  { "Device Name", "srvsvc.srvsvc_NetCharDevGetInfo.device_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileCtr2_array,
	  { "Array", "srvsvc.srvsvc_NetFileCtr2.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessEnum_ctr,
	  { "Ctr", "srvsvc.srvsvc_NetSessEnum.ctr", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1516,
	  { "Info1516", "srvsvc.srvsvc_NetSrvInfo.info1516", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo102_licenses,
	  { "Licenses", "srvsvc.srvsvc_NetSrvInfo102.licenses", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetConnEnum_resume_handle,
	  { "Resume Handle", "srvsvc.srvsvc_NetConnEnum.resume_handle", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetConnCtr_ctr0,
	  { "Ctr0", "srvsvc.srvsvc_NetConnCtr.ctr0", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo101_platform_id,
	  { "Platform Id", "srvsvc.srvsvc_NetSrvInfo101.platform_id", FT_UINT32, BASE_DEC, VALS(srvsvc_srvsvc_PlatformId_vals), 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_chdevs,
	  { "Chdevs", "srvsvc.srvsvc_NetSrvInfo402.chdevs", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_maxnonpagedmemoryusage,
	  { "Maxnonpagedmemoryusage", "srvsvc.srvsvc_NetSrvInfo599.maxnonpagedmemoryusage", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_domain,
	  { "Domain", "srvsvc.srvsvc_NetSrvInfo503.domain", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetPathCanonicalize_pathtype,
	  { "Pathtype", "srvsvc.srvsvc_NetPathCanonicalize.pathtype", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_sizereqbufs,
	  { "Sizereqbufs", "srvsvc.srvsvc_NetSrvInfo503.sizereqbufs", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1018,
	  { "Info1018", "srvsvc.srvsvc_NetSrvInfo.info1018", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevInfo1_device,
	  { "Device", "srvsvc.srvsvc_NetCharDevInfo1.device", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_openfiles,
	  { "Openfiles", "srvsvc.srvsvc_NetSrvInfo403.openfiles", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo0_net_addr,
	  { "Net Addr", "srvsvc.srvsvc_NetTransportInfo0.net_addr", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_shares,
	  { "Shares", "srvsvc.srvsvc_NetSrvInfo402.shares", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_Statistics_pwerrors,
	  { "Pwerrors", "srvsvc.srvsvc_Statistics.pwerrors", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevEnum_ctr,
	  { "Ctr", "srvsvc.srvsvc_NetCharDevEnum.ctr", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1512_maxnonpagedmemoryusage,
	  { "Maxnonpagedmemoryusage", "srvsvc.srvsvc_NetSrvInfo1512.maxnonpagedmemoryusage", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1533,
	  { "Info1533", "srvsvc.srvsvc_NetSrvInfo.info1533", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo502_maxworkitems,
	  { "Maxworkitems", "srvsvc.srvsvc_NetSrvInfo502.maxworkitems", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1549,
	  { "Info1549", "srvsvc.srvsvc_NetSrvInfo.info1549", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_numlockthreads,
	  { "Numlockthreads", "srvsvc.srvsvc_NetSrvInfo599.numlockthreads", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info101,
	  { "Info101", "srvsvc.srvsvc_NetSrvInfo.info101", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetPathCompare_pathtype,
	  { "Pathtype", "srvsvc.srvsvc_NetPathCompare.pathtype", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo_info1005,
	  { "Info1005", "srvsvc.srvsvc_NetShareInfo.info1005", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr1007_count,
	  { "Count", "srvsvc.srvsvc_NetShareCtr1007.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1005,
	  { "Info1005", "srvsvc.srvsvc_NetSrvInfo.info1005", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetPathType_pathflags,
	  { "Pathflags", "srvsvc.srvsvc_NetPathType.pathflags", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_oplockbreakwait,
	  { "Oplockbreakwait", "srvsvc.srvsvc_NetSrvInfo599.oplockbreakwait", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevCtr1_array,
	  { "Array", "srvsvc.srvsvc_NetCharDevCtr1.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQCtr0_array,
	  { "Array", "srvsvc.srvsvc_NetCharDevQCtr0.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetServerTransportAddEx_info,
	  { "Info", "srvsvc.srvsvc_NetServerTransportAddEx.info", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQEnum_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetCharDevQEnum.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileCtr2_count,
	  { "Count", "srvsvc.srvsvc_NetFileCtr2.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetPathCompare_pathflags,
	  { "Pathflags", "srvsvc.srvsvc_NetPathCompare.pathflags", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareDelStart_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetShareDelStart.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetConnInfo1_num_open,
	  { "Num Open", "srvsvc.srvsvc_NetConnInfo1.num_open", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo501_name,
	  { "Name", "srvsvc.srvsvc_NetShareInfo501.name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo_info501,
	  { "Info501", "srvsvc.srvsvc_NetShareInfo.info501", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetPathCompare_path2,
	  { "Path2", "srvsvc.srvsvc_NetPathCompare.path2", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareAdd_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetShareAdd.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo502_maxnonpagedmemoryusage,
	  { "Maxnonpagedmemoryusage", "srvsvc.srvsvc_NetSrvInfo502.maxnonpagedmemoryusage", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessInfo2_client_type,
	  { "Client Type", "srvsvc.srvsvc_NetSessInfo2.client_type", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1554,
	  { "Info1554", "srvsvc.srvsvc_NetSrvInfo.info1554", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_maxworkitemidletime,
	  { "Maxworkitemidletime", "srvsvc.srvsvc_NetSrvInfo599.maxworkitemidletime", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetPathType_path,
	  { "Path", "srvsvc.srvsvc_NetPathType.path", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_DFSFlags_FLAGS_ALLOW_NAMESPACE_CACHING,
	  { "Flags Allow Namespace Caching", "srvsvc.srvsvc_DFSFlags.FLAGS_ALLOW_NAMESPACE_CACHING", FT_BOOLEAN, 32, TFS(&srvsvc_DFSFlags_FLAGS_ALLOW_NAMESPACE_CACHING_tfs), ( 0x00000400 ), NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo102_users,
	  { "Users", "srvsvc.srvsvc_NetSrvInfo102.users", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportCtr_ctr2,
	  { "Ctr2", "srvsvc.srvsvc_NetTransportCtr.ctr2", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_enableforcedlogoff,
	  { "Enableforcedlogoff", "srvsvc.srvsvc_NetSrvInfo503.enableforcedlogoff", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessInfo2_time,
	  { "Time", "srvsvc.srvsvc_NetSessInfo2.time", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetPRNameCompare_name_type,
	  { "Name Type", "srvsvc.srvsvc_NetPRNameCompare.name_type", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetPathCanonicalize_maxbuf,
	  { "Maxbuf", "srvsvc.srvsvc_NetPathCanonicalize.maxbuf", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareGetInfo_share_name,
	  { "Share Name", "srvsvc.srvsvc_NetShareGetInfo.share_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetPRNameCompare_name1,
	  { "Name1", "srvsvc.srvsvc_NetPRNameCompare.name1", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareDelSticky_reserved,
	  { "Reserved", "srvsvc.srvsvc_NetShareDelSticky.reserved", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr1005_array,
	  { "Array", "srvsvc.srvsvc_NetShareCtr1005.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1524_minkeepcomplsearch,
	  { "Minkeepcomplsearch", "srvsvc.srvsvc_NetSrvInfo1524.minkeepcomplsearch", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportDel_unknown,
	  { "Unknown", "srvsvc.srvsvc_NetTransportDel.unknown", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_numlockthreads,
	  { "Numlockthreads", "srvsvc.srvsvc_NetSrvInfo503.numlockthreads", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo502_enableforcedlogoff,
	  { "Enableforcedlogoff", "srvsvc.srvsvc_NetSrvInfo502.enableforcedlogoff", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevCtr_ctr1,
	  { "Ctr1", "srvsvc.srvsvc_NetCharDevCtr.ctr1", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_errortreshold,
	  { "Errortreshold", "srvsvc.srvsvc_NetSrvInfo599.errortreshold", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessInfo1_user_flags,
	  { "User Flags", "srvsvc.srvsvc_NetSessInfo1.user_flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo1004_comment,
	  { "Comment", "srvsvc.srvsvc_NetShareInfo1004.comment", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_Statistics_reqbufneed,
	  { "Reqbufneed", "srvsvc.srvsvc_Statistics.reqbufneed", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_enablesharednetdrives,
	  { "Enablesharednetdrives", "srvsvc.srvsvc_NetSrvInfo599.enablesharednetdrives", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo502_permissions,
	  { "Permissions", "srvsvc.srvsvc_NetShareInfo502.permissions", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileEnum_max_buffer,
	  { "Max Buffer", "srvsvc.srvsvc_NetFileEnum.max_buffer", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo1_addr,
	  { "Addr", "srvsvc.srvsvc_NetTransportInfo1.addr", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo502_type,
	  { "Type", "srvsvc.srvsvc_NetShareInfo502.type", FT_UINT32, BASE_DEC, VALS(srvsvc_srvsvc_ShareType_vals), 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCheck_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetShareCheck.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_DFSFlags_FLAGS_RESTRICT_EXCLUSIVE_OPENS,
	  { "Flags Restrict Exclusive Opens", "srvsvc.srvsvc_DFSFlags.FLAGS_RESTRICT_EXCLUSIVE_OPENS", FT_BOOLEAN, 32, TFS(&srvsvc_DFSFlags_FLAGS_RESTRICT_EXCLUSIVE_OPENS_tfs), ( 0x00000100 ), NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr0_count,
	  { "Count", "srvsvc.srvsvc_NetShareCtr0.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetServerTransportAddEx_level,
	  { "Level", "srvsvc.srvsvc_NetServerTransportAddEx.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevControl_opcode,
	  { "Opcode", "srvsvc.srvsvc_NetCharDevControl.opcode", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetConnCtr1_count,
	  { "Count", "srvsvc.srvsvc_NetConnCtr1.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1516_timesource,
	  { "Timesource", "srvsvc.srvsvc_NetSrvInfo1516.timesource", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQGetInfo_info,
	  { "Info", "srvsvc.srvsvc_NetCharDevQGetInfo.info", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_DFSFlags_SHARE_1005_FLAGS_IN_DFS,
	  { "Share 1005 Flags In Dfs", "srvsvc.srvsvc_DFSFlags.SHARE_1005_FLAGS_IN_DFS", FT_BOOLEAN, 32, TFS(&srvsvc_DFSFlags_SHARE_1005_FLAGS_IN_DFS_tfs), ( 0x00000001 ), NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr_ctr1,
	  { "Ctr1", "srvsvc.srvsvc_NetShareCtr.ctr1", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info503,
	  { "Info503", "srvsvc.srvsvc_NetSrvInfo.info503", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_chdevqs,
	  { "Chdevqs", "srvsvc.srvsvc_NetSrvInfo402.chdevqs", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_rawworkitems,
	  { "Rawworkitems", "srvsvc.srvsvc_NetSrvInfo503.rawworkitems", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1017,
	  { "Info1017", "srvsvc.srvsvc_NetSrvInfo.info1017", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessInfo2_idle_time,
	  { "Idle Time", "srvsvc.srvsvc_NetSessInfo2.idle_time", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo102_comment,
	  { "Comment", "srvsvc.srvsvc_NetSrvInfo102.comment", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_sesssvc,
	  { "Sesssvc", "srvsvc.srvsvc_NetSrvInfo402.sesssvc", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevInfo1_status,
	  { "Status", "srvsvc.srvsvc_NetCharDevInfo1.status", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessEnum_max_buffer,
	  { "Max Buffer", "srvsvc.srvsvc_NetSessEnum.max_buffer", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQPurge_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetCharDevQPurge.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileEnum_path,
	  { "Path", "srvsvc.srvsvc_NetFileEnum.path", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetServerSetServiceBitsEx_servicebits,
	  { "Servicebits", "srvsvc.srvsvc_NetServerSetServiceBitsEx.servicebits", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessCtr0_array,
	  { "Array", "srvsvc.srvsvc_NetSessCtr0.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetPathCompare_path1,
	  { "Path1", "srvsvc.srvsvc_NetPathCompare.path1", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetServerSetServiceBitsEx_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetServerSetServiceBitsEx.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileGetInfo_info,
	  { "Info", "srvsvc.srvsvc_NetFileGetInfo.info", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQCtr_ctr0,
	  { "Ctr0", "srvsvc.srvsvc_NetCharDevQCtr.ctr0", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_connections,
	  { "Connections", "srvsvc.srvsvc_NetSrvInfo403.connections", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_sizereqbufs,
	  { "Sizereqbufs", "srvsvc.srvsvc_NetSrvInfo599.sizereqbufs", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileCtr_ctr3,
	  { "Ctr3", "srvsvc.srvsvc_NetFileCtr.ctr3", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_initfiletable,
	  { "Initfiletable", "srvsvc.srvsvc_NetSrvInfo599.initfiletable", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1528_scavtimeout,
	  { "Scavtimeout", "srvsvc.srvsvc_NetSrvInfo1528.scavtimeout", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevEnum_resume_handle,
	  { "Resume Handle", "srvsvc.srvsvc_NetCharDevEnum.resume_handle", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetPathCanonicalize_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetPathCanonicalize.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo2_password,
	  { "Password", "srvsvc.srvsvc_NetShareInfo2.password", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevCtr_ctr0,
	  { "Ctr0", "srvsvc.srvsvc_NetCharDevCtr.ctr0", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileClose_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetFileClose.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_lmannounce,
	  { "Lmannounce", "srvsvc.srvsvc_NetSrvInfo503.lmannounce", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportEnum_resume_handle,
	  { "Resume Handle", "srvsvc.srvsvc_NetTransportEnum.resume_handle", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareDelStart_share,
	  { "Share", "srvsvc.srvsvc_NetShareDelStart.share", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessInfo2_num_open,
	  { "Num Open", "srvsvc.srvsvc_NetSessInfo2.num_open", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo101_server_name,
	  { "Server Name", "srvsvc.srvsvc_NetSrvInfo101.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportCtr_ctr3,
	  { "Ctr3", "srvsvc.srvsvc_NetTransportCtr.ctr3", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr2_count,
	  { "Count", "srvsvc.srvsvc_NetShareCtr2.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1518,
	  { "Info1518", "srvsvc.srvsvc_NetSrvInfo.info1518", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_netioalert,
	  { "Netioalert", "srvsvc.srvsvc_NetSrvInfo402.netioalert", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo_info1004,
	  { "Info1004", "srvsvc.srvsvc_NetShareInfo.info1004", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_numadmin,
	  { "Numadmin", "srvsvc.srvsvc_NetSrvInfo402.numadmin", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_lmannounce,
	  { "Lmannounce", "srvsvc.srvsvc_NetSrvInfo599.lmannounce", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_sizereqbufs,
	  { "Sizereqbufs", "srvsvc.srvsvc_NetSrvInfo402.sizereqbufs", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1523,
	  { "Info1523", "srvsvc.srvsvc_NetSrvInfo.info1523", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSetFileSecurity_share,
	  { "Share", "srvsvc.srvsvc_NetSetFileSecurity.share", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo502_maxrawbuflen,
	  { "Maxrawbuflen", "srvsvc.srvsvc_NetSrvInfo502.maxrawbuflen", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1548,
	  { "Info1548", "srvsvc.srvsvc_NetSrvInfo.info1548", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetRemoteTOD_info,
	  { "Info", "srvsvc.srvsvc_NetRemoteTOD.info", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetConnEnum_ctr,
	  { "Ctr", "srvsvc.srvsvc_NetConnEnum.ctr", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessCtr1_count,
	  { "Count", "srvsvc.srvsvc_NetSessCtr1.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1518_lmannounce,
	  { "Lmannounce", "srvsvc.srvsvc_NetSrvInfo1518.lmannounce", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessInfo2_user,
	  { "User", "srvsvc.srvsvc_NetSessInfo2.user", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo1_vcs,
	  { "Vcs", "srvsvc.srvsvc_NetTransportInfo1.vcs", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQPurgeSelf_queue_name,
	  { "Queue Name", "srvsvc.srvsvc_NetCharDevQPurgeSelf.queue_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetConnInfo1_num_users,
	  { "Num Users", "srvsvc.srvsvc_NetConnInfo1.num_users", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportDel_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetTransportDel.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_sessopen,
	  { "Sessopen", "srvsvc.srvsvc_NetSrvInfo503.sessopen", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevCtr0_count,
	  { "Count", "srvsvc.srvsvc_NetCharDevCtr0.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessCtr1_array,
	  { "Array", "srvsvc.srvsvc_NetSessCtr1.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_initconntable,
	  { "Initconntable", "srvsvc.srvsvc_NetSrvInfo599.initconntable", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareSetInfo_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetShareSetInfo.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1545,
	  { "Info1545", "srvsvc.srvsvc_NetSrvInfo.info1545", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1553,
	  { "Info1553", "srvsvc.srvsvc_NetSrvInfo.info1553", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessEnum_resume_handle,
	  { "Resume Handle", "srvsvc.srvsvc_NetSessEnum.resume_handle", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1514,
	  { "Info1514", "srvsvc.srvsvc_NetSrvInfo.info1514", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareSetInfo_level,
	  { "Level", "srvsvc.srvsvc_NetShareSetInfo.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_Statistics_fopens,
	  { "Fopens", "srvsvc.srvsvc_Statistics.fopens", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1016,
	  { "Info1016", "srvsvc.srvsvc_NetSrvInfo.info1016", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_maxworkitems,
	  { "Maxworkitems", "srvsvc.srvsvc_NetSrvInfo599.maxworkitems", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetDiskInfo_count,
	  { "Count", "srvsvc.srvsvc_NetDiskInfo.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_glist_mtime,
	  { "Glist Mtime", "srvsvc.srvsvc_NetSrvInfo402.glist_mtime", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_Statistics_bigbufneed,
	  { "Bigbufneed", "srvsvc.srvsvc_Statistics.bigbufneed", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr_ctr2,
	  { "Ctr2", "srvsvc.srvsvc_NetShareCtr.ctr2", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1510_sessusers,
	  { "Sessusers", "srvsvc.srvsvc_NetSrvInfo1510.sessusers", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportDel_transport,
	  { "Transport", "srvsvc.srvsvc_NetTransportDel.transport", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo502_enablesoftcompat,
	  { "Enablesoftcompat", "srvsvc.srvsvc_NetSrvInfo502.enablesoftcompat", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetPathType_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetPathType.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1513_maxpagedmemoryusage,
	  { "Maxpagedmemoryusage", "srvsvc.srvsvc_NetSrvInfo1513.maxpagedmemoryusage", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetServerStatisticsGet_service,
	  { "Service", "srvsvc.srvsvc_NetServerStatisticsGet.service", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportCtr3_array,
	  { "Array", "srvsvc.srvsvc_NetTransportCtr3.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQInfo1_devices,
	  { "Devices", "srvsvc.srvsvc_NetCharDevQInfo1.devices", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_SessionUserFlags_SESS_GUEST,
	  { "Sess Guest", "srvsvc.srvsvc_SessionUserFlags.SESS_GUEST", FT_BOOLEAN, 32, TFS(&srvsvc_SessionUserFlags_SESS_GUEST_tfs), ( 0x00000001 ), NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessInfo502_client_type,
	  { "Client Type", "srvsvc.srvsvc_NetSessInfo502.client_type", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_activelocks,
	  { "Activelocks", "srvsvc.srvsvc_NetSrvInfo403.activelocks", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetServerStatisticsGet_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetServerStatisticsGet.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessCtr_ctr502,
	  { "Ctr502", "srvsvc.srvsvc_NetSessCtr.ctr502", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_netioalert,
	  { "Netioalert", "srvsvc.srvsvc_NetSrvInfo403.netioalert", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1553_minlinkthroughput,
	  { "Minlinkthroughput", "srvsvc.srvsvc_NetSrvInfo1553.minlinkthroughput", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo2_current_users,
	  { "Current Users", "srvsvc.srvsvc_NetShareInfo2.current_users", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo502_sessusers,
	  { "Sessusers", "srvsvc.srvsvc_NetSrvInfo502.sessusers", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_irpstacksize,
	  { "Irpstacksize", "srvsvc.srvsvc_NetSrvInfo599.irpstacksize", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQSetInfo_info,
	  { "Info", "srvsvc.srvsvc_NetCharDevQSetInfo.info", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_sizereqbufs,
	  { "Sizereqbufs", "srvsvc.srvsvc_NetSrvInfo403.sizereqbufs", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1530_minfreeworkitems,
	  { "Minfreeworkitems", "srvsvc.srvsvc_NetSrvInfo1530.minfreeworkitems", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo2_max_users,
	  { "Max Users", "srvsvc.srvsvc_NetShareInfo2.max_users", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo2_domain,
	  { "Domain", "srvsvc.srvsvc_NetTransportInfo2.domain", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo2_type,
	  { "Type", "srvsvc.srvsvc_NetShareInfo2.type", FT_UINT32, BASE_DEC, VALS(srvsvc_srvsvc_ShareType_vals), 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_minrcvqueue,
	  { "Minrcvqueue", "srvsvc.srvsvc_NetSrvInfo599.minrcvqueue", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessCtr0_count,
	  { "Count", "srvsvc.srvsvc_NetSessCtr0.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevControl_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetCharDevControl.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo2_name,
	  { "Name", "srvsvc.srvsvc_NetShareInfo2.name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_maxcopywritelen,
	  { "Maxcopywritelen", "srvsvc.srvsvc_NetSrvInfo599.maxcopywritelen", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevGetInfo_info,
	  { "Info", "srvsvc.srvsvc_NetCharDevGetInfo.info", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo502_sizereqbufs,
	  { "Sizereqbufs", "srvsvc.srvsvc_NetSrvInfo502.sizereqbufs", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo3_password_len,
	  { "Password Len", "srvsvc.srvsvc_NetTransportInfo3.password_len", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevInfo1_user,
	  { "User", "srvsvc.srvsvc_NetCharDevInfo1.user", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_security,
	  { "Security", "srvsvc.srvsvc_NetSrvInfo403.security", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevGetInfo_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetCharDevGetInfo.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessDel_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetSessDel.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1547_alertsched,
	  { "Alertsched", "srvsvc.srvsvc_NetSrvInfo1547.alertsched", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1546,
	  { "Info1546", "srvsvc.srvsvc_NetSrvInfo.info1546", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQGetInfo_level,
	  { "Level", "srvsvc.srvsvc_NetCharDevQGetInfo.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo502_unknown,
	  { "Unknown", "srvsvc.srvsvc_NetShareInfo502.unknown", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_Statistics_avresponse,
	  { "Avresponse", "srvsvc.srvsvc_Statistics.avresponse", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareDel_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetShareDel.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo2_addr_len,
	  { "Addr Len", "srvsvc.srvsvc_NetTransportInfo2.addr_len", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_alerts,
	  { "Alerts", "srvsvc.srvsvc_NetSrvInfo403.alerts", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevControl_device_name,
	  { "Device Name", "srvsvc.srvsvc_NetCharDevControl.device_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo502_sessopen,
	  { "Sessopen", "srvsvc.srvsvc_NetSrvInfo502.sessopen", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_enableraw,
	  { "Enableraw", "srvsvc.srvsvc_NetSrvInfo599.enableraw", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1523_maxkeepsearch,
	  { "Maxkeepsearch", "srvsvc.srvsvc_NetSrvInfo1523.maxkeepsearch", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_sessopen,
	  { "Sessopen", "srvsvc.srvsvc_NetSrvInfo403.sessopen", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1107_users,
	  { "Users", "srvsvc.srvsvc_NetSrvInfo1107.users", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_scavtimeout,
	  { "Scavtimeout", "srvsvc.srvsvc_NetSrvInfo599.scavtimeout", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1520_maxcopyreadlen,
	  { "Maxcopyreadlen", "srvsvc.srvsvc_NetSrvInfo1520.maxcopyreadlen", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1506,
	  { "Info1506", "srvsvc.srvsvc_NetSrvInfo.info1506", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessInfo0_client,
	  { "Client", "srvsvc.srvsvc_NetSessInfo0.client", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_initsearchtable,
	  { "Initsearchtable", "srvsvc.srvsvc_NetSrvInfo599.initsearchtable", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_maxworkitems,
	  { "Maxworkitems", "srvsvc.srvsvc_NetSrvInfo503.maxworkitems", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_reserved,
	  { "Reserved", "srvsvc.srvsvc_NetSrvInfo599.reserved", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvSetInfo_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetSrvSetInfo.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileEnum_user,
	  { "User", "srvsvc.srvsvc_NetFileEnum.user", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo502_path,
	  { "Path", "srvsvc.srvsvc_NetShareInfo502.path", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileInfo3_fid,
	  { "Fid", "srvsvc.srvsvc_NetFileInfo3.fid", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1538,
	  { "Info1538", "srvsvc.srvsvc_NetSrvInfo.info1538", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_Statistics_permerrors,
	  { "Permerrors", "srvsvc.srvsvc_Statistics.permerrors", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportAdd_info,
	  { "Info", "srvsvc.srvsvc_NetTransportAdd.info", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetDiskEnum_resume_handle,
	  { "Resume Handle", "srvsvc.srvsvc_NetDiskEnum.resume_handle", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo0_vcs,
	  { "Vcs", "srvsvc.srvsvc_NetTransportInfo0.vcs", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileInfo3_path,
	  { "Path", "srvsvc.srvsvc_NetFileInfo3.path", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevEnum_level,
	  { "Level", "srvsvc.srvsvc_NetCharDevEnum.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo1_name,
	  { "Name", "srvsvc.srvsvc_NetShareInfo1.name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQEnum_ctr,
	  { "Ctr", "srvsvc.srvsvc_NetCharDevQEnum.ctr", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessCtr10_count,
	  { "Count", "srvsvc.srvsvc_NetSessCtr10.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_sec_desc_buf_len,
	  { "Sec Desc Buf Len", "srvsvc.sec_desc_buf_len", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr_ctr1005,
	  { "Ctr1005", "srvsvc.srvsvc_NetShareCtr.ctr1005", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_sessconns,
	  { "Sessconns", "srvsvc.srvsvc_NetSrvInfo503.sessconns", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_initworkitems,
	  { "Initworkitems", "srvsvc.srvsvc_NetSrvInfo599.initworkitems", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevEnum_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetCharDevEnum.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo502_password,
	  { "Password", "srvsvc.srvsvc_NetShareInfo502.password", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1521_maxcopywritelen,
	  { "Maxcopywritelen", "srvsvc.srvsvc_NetSrvInfo1521.maxcopywritelen", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_minkeepsearch,
	  { "Minkeepsearch", "srvsvc.srvsvc_NetSrvInfo599.minkeepsearch", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_srvheuristics,
	  { "Srvheuristics", "srvsvc.srvsvc_NetSrvInfo403.srvheuristics", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo_info2,
	  { "Info2", "srvsvc.srvsvc_NetTransportInfo.info2", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_lanmask,
	  { "Lanmask", "srvsvc.srvsvc_NetSrvInfo403.lanmask", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1541,
	  { "Info1541", "srvsvc.srvsvc_NetSrvInfo.info1541", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessCtr_ctr2,
	  { "Ctr2", "srvsvc.srvsvc_NetSessCtr.ctr2", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo1_comment,
	  { "Comment", "srvsvc.srvsvc_NetShareInfo1.comment", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessCtr502_count,
	  { "Count", "srvsvc.srvsvc_NetSessCtr502.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1506_maxworkitems,
	  { "Maxworkitems", "srvsvc.srvsvc_NetSrvInfo1506.maxworkitems", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo502_current_users,
	  { "Current Users", "srvsvc.srvsvc_NetShareInfo502.current_users", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetServerStatisticsGet_stat,
	  { "Stat", "srvsvc.srvsvc_NetServerStatisticsGet.stat", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQInfo_info1,
	  { "Info1", "srvsvc.srvsvc_NetCharDevQInfo.info1", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessEnum_totalentries,
	  { "Totalentries", "srvsvc.srvsvc_NetSessEnum.totalentries", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_chdevs,
	  { "Chdevs", "srvsvc.srvsvc_NetSrvInfo403.chdevs", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevEnum_max_buffer,
	  { "Max Buffer", "srvsvc.srvsvc_NetCharDevEnum.max_buffer", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info402,
	  { "Info402", "srvsvc.srvsvc_NetSrvInfo.info402", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo2_name,
	  { "Name", "srvsvc.srvsvc_NetTransportInfo2.name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_enablesoftcompat,
	  { "Enablesoftcompat", "srvsvc.srvsvc_NetSrvInfo503.enablesoftcompat", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo_info3,
	  { "Info3", "srvsvc.srvsvc_NetTransportInfo.info3", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetRemoteTODInfo_month,
	  { "Month", "srvsvc.srvsvc_NetRemoteTODInfo.month", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1501_sessopens,
	  { "Sessopens", "srvsvc.srvsvc_NetSrvInfo1501.sessopens", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_werror,
	  { "Windows Error", "srvsvc.werror", FT_UINT32, BASE_HEX, VALS(WERR_errors), 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetRemoteTODInfo_day,
	  { "Day", "srvsvc.srvsvc_NetRemoteTODInfo.day", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetNameValidate_flags,
	  { "Flags", "srvsvc.srvsvc_NetNameValidate.flags", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileInfo3_permissions,
	  { "Permissions", "srvsvc.srvsvc_NetFileInfo3.permissions", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_sessusers,
	  { "Sessusers", "srvsvc.srvsvc_NetSrvInfo503.sessusers", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetConnEnum_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetConnEnum.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_enableoplocks,
	  { "Enableoplocks", "srvsvc.srvsvc_NetSrvInfo503.enableoplocks", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo100_platform_id,
	  { "Platform Id", "srvsvc.srvsvc_NetSrvInfo100.platform_id", FT_UINT32, BASE_DEC, VALS(srvsvc_srvsvc_PlatformId_vals), 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessCtr502_array,
	  { "Array", "srvsvc.srvsvc_NetSessCtr502.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetRemoteTODInfo_msecs,
	  { "Msecs", "srvsvc.srvsvc_NetRemoteTODInfo.msecs", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_irpstacksize,
	  { "Irpstacksize", "srvsvc.srvsvc_NetSrvInfo503.irpstacksize", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_enableraw,
	  { "Enableraw", "srvsvc.srvsvc_NetSrvInfo503.enableraw", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetServerStatisticsGet_level,
	  { "Level", "srvsvc.srvsvc_NetServerStatisticsGet.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_sesssvc,
	  { "Sesssvc", "srvsvc.srvsvc_NetSrvInfo403.sesssvc", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetServerStatisticsGet_options,
	  { "Options", "srvsvc.srvsvc_NetServerStatisticsGet.options", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info102,
	  { "Info102", "srvsvc.srvsvc_NetSrvInfo.info102", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_Statistics_bytesrcvd_high,
	  { "Bytesrcvd High", "srvsvc.srvsvc_Statistics.bytesrcvd_high", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_numbigbufs,
	  { "Numbigbufs", "srvsvc.srvsvc_NetSrvInfo403.numbigbufs", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetPathCanonicalize_can_path,
	  { "Can Path", "srvsvc.srvsvc_NetPathCanonicalize.can_path", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo_info1,
	  { "Info1", "srvsvc.srvsvc_NetShareInfo.info1", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportEnum_totalentries,
	  { "Totalentries", "srvsvc.srvsvc_NetTransportEnum.totalentries", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr1007_array,
	  { "Array", "srvsvc.srvsvc_NetShareCtr1007.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareEnumAll_resume_handle,
	  { "Resume Handle", "srvsvc.srvsvc_NetShareEnumAll.resume_handle", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetPRNameCompare_flags,
	  { "Flags", "srvsvc.srvsvc_NetPRNameCompare.flags", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetPathType_pathtype,
	  { "Pathtype", "srvsvc.srvsvc_NetPathType.pathtype", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1533_maxmpxct,
	  { "Maxmpxct", "srvsvc.srvsvc_NetSrvInfo1533.maxmpxct", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_Statistics_devopens,
	  { "Devopens", "srvsvc.srvsvc_Statistics.devopens", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1556,
	  { "Info1556", "srvsvc.srvsvc_NetSrvInfo.info1556", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQEnum_max_buffer,
	  { "Max Buffer", "srvsvc.srvsvc_NetCharDevQEnum.max_buffer", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetConnEnum_path,
	  { "Path", "srvsvc.srvsvc_NetConnEnum.path", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_sessopen,
	  { "Sessopen", "srvsvc.srvsvc_NetSrvInfo402.sessopen", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo102_disc,
	  { "Disc", "srvsvc.srvsvc_NetSrvInfo102.disc", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetFileInfo3_num_locks,
	  { "Num Locks", "srvsvc.srvsvc_NetFileInfo3.num_locks", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo3_net_addr,
	  { "Net Addr", "srvsvc.srvsvc_NetTransportInfo3.net_addr", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvSetInfo_level,
	  { "Level", "srvsvc.srvsvc_NetSrvSetInfo.level", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr1006_array,
	  { "Array", "srvsvc.srvsvc_NetShareCtr1006.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo402_sessreqs,
	  { "Sessreqs", "srvsvc.srvsvc_NetSrvInfo402.sessreqs", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_autopath,
	  { "Autopath", "srvsvc.srvsvc_NetSrvInfo403.autopath", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo102_server_name,
	  { "Server Name", "srvsvc.srvsvc_NetSrvInfo102.server_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1546_initsearchtable,
	  { "Initsearchtable", "srvsvc.srvsvc_NetSrvInfo1546.initsearchtable", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr1005_count,
	  { "Count", "srvsvc.srvsvc_NetShareCtr1005.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo2_path,
	  { "Path", "srvsvc.srvsvc_NetShareInfo2.path", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessEnum_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetSessEnum.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_chdevqs,
	  { "Chdevqs", "srvsvc.srvsvc_NetSrvInfo403.chdevqs", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo2_net_addr,
	  { "Net Addr", "srvsvc.srvsvc_NetTransportInfo2.net_addr", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetServerSetServiceBitsEx_transport,
	  { "Transport", "srvsvc.srvsvc_NetServerSetServiceBitsEx.transport", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_logonalert,
	  { "Logonalert", "srvsvc.srvsvc_NetSrvInfo403.logonalert", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo403_auditprofile,
	  { "Auditprofile", "srvsvc.srvsvc_NetSrvInfo403.auditprofile", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_enablefcbopens,
	  { "Enablefcbopens", "srvsvc.srvsvc_NetSrvInfo599.enablefcbopens", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessEnum_user,
	  { "User", "srvsvc.srvsvc_NetSessEnum.user", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetRemoteTODInfo_timezone,
	  { "Timezone", "srvsvc.srvsvc_NetRemoteTODInfo.timezone", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_oplockbreakresponsewait,
	  { "Oplockbreakresponsewait", "srvsvc.srvsvc_NetSrvInfo503.oplockbreakresponsewait", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo1_net_addr,
	  { "Net Addr", "srvsvc.srvsvc_NetTransportInfo1.net_addr", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_DFSFlags_CSC_CACHE_AUTO_REINT,
	  { "Csc Cache Auto Reint", "srvsvc.srvsvc_DFSFlags.CSC_CACHE_AUTO_REINT", FT_BOOLEAN, 32, TFS(&srvsvc_DFSFlags_CSC_CACHE_AUTO_REINT_tfs), ( 0x00000010 ), NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQGetInfo_user,
	  { "User", "srvsvc.srvsvc_NetCharDevQGetInfo.user", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo503_maxkeepsearch,
	  { "Maxkeepsearch", "srvsvc.srvsvc_NetSrvInfo503.maxkeepsearch", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQCtr0_count,
	  { "Count", "srvsvc.srvsvc_NetCharDevQCtr0.count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1503_opensearch,
	  { "Opensearch", "srvsvc.srvsvc_NetSrvInfo1503.opensearch", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo102_userpath,
	  { "Userpath", "srvsvc.srvsvc_NetSrvInfo102.userpath", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1555,
	  { "Info1555", "srvsvc.srvsvc_NetSrvInfo.info1555", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessInfo10_user,
	  { "User", "srvsvc.srvsvc_NetSessInfo10.user", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo599_alertsched,
	  { "Alertsched", "srvsvc.srvsvc_NetSrvInfo599.alertsched", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetPathCompare_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetPathCompare.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1547,
	  { "Info1547", "srvsvc.srvsvc_NetSrvInfo.info1547", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportInfo1_name,
	  { "Name", "srvsvc.srvsvc_NetTransportInfo1.name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo502_max_users,
	  { "Max Users", "srvsvc.srvsvc_NetShareInfo502.max_users", FT_INT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo502_opensearch,
	  { "Opensearch", "srvsvc.srvsvc_NetSrvInfo502.opensearch", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_DFSFlags_FLAGS_ACCESS_BASED_DIRECTORY_ENUM,
	  { "Flags Access Based Directory Enum", "srvsvc.srvsvc_DFSFlags.FLAGS_ACCESS_BASED_DIRECTORY_ENUM", FT_BOOLEAN, 32, TFS(&srvsvc_DFSFlags_FLAGS_ACCESS_BASED_DIRECTORY_ENUM_tfs), ( 0x00000800 ), NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQInfo_info0,
	  { "Info0", "srvsvc.srvsvc_NetCharDevQInfo.info0", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo102_hidden,
	  { "Hidden", "srvsvc.srvsvc_NetSrvInfo102.hidden", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr_ctr1501,
	  { "Ctr1501", "srvsvc.srvsvc_NetShareCtr.ctr1501", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1539,
	  { "Info1539", "srvsvc.srvsvc_NetSrvInfo.info1539", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo501_comment,
	  { "Comment", "srvsvc.srvsvc_NetShareInfo501.comment", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportEnum_transports,
	  { "Transports", "srvsvc.srvsvc_NetTransportEnum.transports", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetTransportCtr2_array,
	  { "Array", "srvsvc.srvsvc_NetTransportCtr2.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareInfo502_name,
	  { "Name", "srvsvc.srvsvc_NetShareInfo502.name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1535_oplockbreakresponsewait,
	  { "Oplockbreakresponsewait", "srvsvc.srvsvc_NetSrvInfo1535.oplockbreakresponsewait", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQInfo1_users,
	  { "Users", "srvsvc.srvsvc_NetCharDevQInfo1.users", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSessCtr_ctr1,
	  { "Ctr1", "srvsvc.srvsvc_NetSessCtr.ctr1", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQPurgeSelf_server_unc,
	  { "Server Unc", "srvsvc.srvsvc_NetCharDevQPurgeSelf.server_unc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo1010_disc,
	  { "Disc", "srvsvc.srvsvc_NetSrvInfo1010.disc", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetCharDevQPurgeSelf_computer_name,
	  { "Computer Name", "srvsvc.srvsvc_NetCharDevQPurgeSelf.computer_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo101_server_type,
	  { "Server Type", "srvsvc.srvsvc_NetSrvInfo101.server_type", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetShareCtr502_array,
	  { "Array", "srvsvc.srvsvc_NetShareCtr502.array", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_srvsvc_srvsvc_NetSrvInfo_info1530,
	  { "Info1530", "srvsvc.srvsvc_NetSrvInfo.info1530", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	};


	static gint *ett[] = {
		&ett_dcerpc_srvsvc,
		&ett_srvsvc_srvsvc_NetCharDevInfo0,
		&ett_srvsvc_srvsvc_NetCharDevCtr0,
		&ett_srvsvc_srvsvc_NetCharDevInfo1,
		&ett_srvsvc_srvsvc_NetCharDevCtr1,
		&ett_srvsvc_srvsvc_NetCharDevInfo,
		&ett_srvsvc_srvsvc_NetCharDevCtr,
		&ett_srvsvc_srvsvc_NetCharDevQInfo0,
		&ett_srvsvc_srvsvc_NetCharDevQCtr0,
		&ett_srvsvc_srvsvc_NetCharDevQInfo1,
		&ett_srvsvc_srvsvc_NetCharDevQCtr1,
		&ett_srvsvc_srvsvc_NetCharDevQInfo,
		&ett_srvsvc_srvsvc_NetCharDevQCtr,
		&ett_srvsvc_srvsvc_NetConnInfo0,
		&ett_srvsvc_srvsvc_NetConnCtr0,
		&ett_srvsvc_srvsvc_NetConnInfo1,
		&ett_srvsvc_srvsvc_NetConnCtr1,
		&ett_srvsvc_srvsvc_NetConnCtr,
		&ett_srvsvc_srvsvc_NetFileInfo2,
		&ett_srvsvc_srvsvc_NetFileCtr2,
		&ett_srvsvc_srvsvc_NetFileInfo3,
		&ett_srvsvc_srvsvc_NetFileCtr3,
		&ett_srvsvc_srvsvc_NetFileInfo,
		&ett_srvsvc_srvsvc_NetFileCtr,
		&ett_srvsvc_srvsvc_SessionUserFlags,
		&ett_srvsvc_srvsvc_NetSessInfo0,
		&ett_srvsvc_srvsvc_NetSessCtr0,
		&ett_srvsvc_srvsvc_NetSessInfo1,
		&ett_srvsvc_srvsvc_NetSessCtr1,
		&ett_srvsvc_srvsvc_NetSessInfo2,
		&ett_srvsvc_srvsvc_NetSessCtr2,
		&ett_srvsvc_srvsvc_NetSessInfo10,
		&ett_srvsvc_srvsvc_NetSessCtr10,
		&ett_srvsvc_srvsvc_NetSessInfo502,
		&ett_srvsvc_srvsvc_NetSessCtr502,
		&ett_srvsvc_srvsvc_NetSessCtr,
		&ett_srvsvc_srvsvc_NetShareInfo0,
		&ett_srvsvc_srvsvc_NetShareInfo1,
		&ett_srvsvc_srvsvc_NetShareInfo2,
		&ett_srvsvc_srvsvc_NetShareInfo501,
		&ett_srvsvc_srvsvc_NetShareInfo502,
		&ett_srvsvc_srvsvc_NetShareInfo1004,
		&ett_srvsvc_srvsvc_NetShareInfo1006,
		&ett_srvsvc_srvsvc_DFSFlags,
		&ett_srvsvc_srvsvc_NetShareCtr0,
		&ett_srvsvc_srvsvc_NetShareCtr1,
		&ett_srvsvc_srvsvc_NetShareCtr2,
		&ett_srvsvc_srvsvc_NetShareCtr501,
		&ett_srvsvc_srvsvc_NetShareCtr502,
		&ett_srvsvc_srvsvc_NetShareCtr1004,
		&ett_srvsvc_srvsvc_NetShareInfo1005,
		&ett_srvsvc_srvsvc_NetShareCtr1005,
		&ett_srvsvc_srvsvc_NetShareCtr1006,
		&ett_srvsvc_srvsvc_NetShareInfo1007,
		&ett_srvsvc_srvsvc_NetShareCtr1007,
		&ett_srvsvc_srvsvc_NetShareCtr1501,
		&ett_srvsvc_srvsvc_NetShareInfo,
		&ett_srvsvc_srvsvc_NetShareCtr,
		&ett_srvsvc_srvsvc_NetSrvInfo100,
		&ett_srvsvc_srvsvc_NetSrvInfo101,
		&ett_srvsvc_srvsvc_NetSrvInfo102,
		&ett_srvsvc_srvsvc_NetSrvInfo402,
		&ett_srvsvc_srvsvc_NetSrvInfo403,
		&ett_srvsvc_srvsvc_NetSrvInfo502,
		&ett_srvsvc_srvsvc_NetSrvInfo503,
		&ett_srvsvc_srvsvc_NetSrvInfo599,
		&ett_srvsvc_srvsvc_NetSrvInfo1005,
		&ett_srvsvc_srvsvc_NetSrvInfo1010,
		&ett_srvsvc_srvsvc_NetSrvInfo1016,
		&ett_srvsvc_srvsvc_NetSrvInfo1017,
		&ett_srvsvc_srvsvc_NetSrvInfo1018,
		&ett_srvsvc_srvsvc_NetSrvInfo1107,
		&ett_srvsvc_srvsvc_NetSrvInfo1501,
		&ett_srvsvc_srvsvc_NetSrvInfo1502,
		&ett_srvsvc_srvsvc_NetSrvInfo1503,
		&ett_srvsvc_srvsvc_NetSrvInfo1506,
		&ett_srvsvc_srvsvc_NetSrvInfo1509,
		&ett_srvsvc_srvsvc_NetSrvInfo1510,
		&ett_srvsvc_srvsvc_NetSrvInfo1511,
		&ett_srvsvc_srvsvc_NetSrvInfo1512,
		&ett_srvsvc_srvsvc_NetSrvInfo1513,
		&ett_srvsvc_srvsvc_NetSrvInfo1514,
		&ett_srvsvc_srvsvc_NetSrvInfo1515,
		&ett_srvsvc_srvsvc_NetSrvInfo1516,
		&ett_srvsvc_srvsvc_NetSrvInfo1518,
		&ett_srvsvc_srvsvc_NetSrvInfo1520,
		&ett_srvsvc_srvsvc_NetSrvInfo1521,
		&ett_srvsvc_srvsvc_NetSrvInfo1522,
		&ett_srvsvc_srvsvc_NetSrvInfo1523,
		&ett_srvsvc_srvsvc_NetSrvInfo1524,
		&ett_srvsvc_srvsvc_NetSrvInfo1525,
		&ett_srvsvc_srvsvc_NetSrvInfo1528,
		&ett_srvsvc_srvsvc_NetSrvInfo1529,
		&ett_srvsvc_srvsvc_NetSrvInfo1530,
		&ett_srvsvc_srvsvc_NetSrvInfo1533,
		&ett_srvsvc_srvsvc_NetSrvInfo1534,
		&ett_srvsvc_srvsvc_NetSrvInfo1535,
		&ett_srvsvc_srvsvc_NetSrvInfo1536,
		&ett_srvsvc_srvsvc_NetSrvInfo1537,
		&ett_srvsvc_srvsvc_NetSrvInfo1538,
		&ett_srvsvc_srvsvc_NetSrvInfo1539,
		&ett_srvsvc_srvsvc_NetSrvInfo1540,
		&ett_srvsvc_srvsvc_NetSrvInfo1541,
		&ett_srvsvc_srvsvc_NetSrvInfo1542,
		&ett_srvsvc_srvsvc_NetSrvInfo1543,
		&ett_srvsvc_srvsvc_NetSrvInfo1544,
		&ett_srvsvc_srvsvc_NetSrvInfo1545,
		&ett_srvsvc_srvsvc_NetSrvInfo1546,
		&ett_srvsvc_srvsvc_NetSrvInfo1547,
		&ett_srvsvc_srvsvc_NetSrvInfo1548,
		&ett_srvsvc_srvsvc_NetSrvInfo1549,
		&ett_srvsvc_srvsvc_NetSrvInfo1550,
		&ett_srvsvc_srvsvc_NetSrvInfo1552,
		&ett_srvsvc_srvsvc_NetSrvInfo1553,
		&ett_srvsvc_srvsvc_NetSrvInfo1554,
		&ett_srvsvc_srvsvc_NetSrvInfo1555,
		&ett_srvsvc_srvsvc_NetSrvInfo1556,
		&ett_srvsvc_srvsvc_NetSrvInfo,
		&ett_srvsvc_srvsvc_NetDiskInfo0,
		&ett_srvsvc_srvsvc_NetDiskInfo,
		&ett_srvsvc_srvsvc_Statistics,
		&ett_srvsvc_srvsvc_NetTransportInfo0,
		&ett_srvsvc_srvsvc_NetTransportCtr0,
		&ett_srvsvc_srvsvc_NetTransportInfo1,
		&ett_srvsvc_srvsvc_NetTransportCtr1,
		&ett_srvsvc_srvsvc_TransportFlags,
		&ett_srvsvc_srvsvc_NetTransportInfo2,
		&ett_srvsvc_srvsvc_NetTransportCtr2,
		&ett_srvsvc_srvsvc_NetTransportInfo3,
		&ett_srvsvc_srvsvc_NetTransportCtr3,
		&ett_srvsvc_srvsvc_NetTransportCtr,
		&ett_srvsvc_srvsvc_NetRemoteTODInfo,
		&ett_srvsvc_srvsvc_NetTransportInfo,
	};

	proto_dcerpc_srvsvc = proto_register_protocol("Server Service", "SRVSVC", "srvsvc");
	proto_register_field_array(proto_dcerpc_srvsvc, hf, array_length (hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_dcerpc_srvsvc(void)
{
	dcerpc_init_uuid(proto_dcerpc_srvsvc, ett_dcerpc_srvsvc,
		&uuid_dcerpc_srvsvc, ver_dcerpc_srvsvc,
		srvsvc_dissectors, hf_srvsvc_opnum);
}
