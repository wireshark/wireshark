/* packet-dcerpc-lsa.h
 * Routines for SMB \PIPE\lsarpc packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __PACKET_DCERPC_LSA_H
#define __PACKET_DCERPC_LSA_H

#define LSA_LSARCLOSE				0x00
#define LSA_LSARDELETE				0x01
#define LSA_LSARENUMERATEPRIVILEGES		0x02
#define LSA_LSARQUERYSECURITYOBJECT		0x03
#define LSA_LSARSETSECURITYOBJECT		0x04
#define LSA_LSARCHANGEPASSWORD			0x05
#define LSA_LSAROPENPOLICY			0x06
#define LSA_LSARQUERYINFORMATIONPOLICY		0x07
#define LSA_LSARSETINFORMATIONPOLICY		0x08
#define LSA_LSARCLEARAUDITLOG			0x09
#define LSA_LSARCREATEACCOUNT			0x0a
#define LSA_LSARENUMERATEACCOUNTS		0x0b
#define LSA_LSARCREATETRUSTEDDOMAIN		0x0c
#define LSA_LSARENUMERATETRUSTEDDOMAINS		0x0d
#define LSA_LSARLOOKUPNAMES			0x0e
#define LSA_LSARLOOKUPSIDS			0x0f
#define LSA_LSARCREATESECRET			0x10
#define LSA_LSAROPENACCOUNT			0x11
#define LSA_LSARENUMERATEPRIVILEGESACCOUNT	0x12
#define LSA_LSARADDPRIVILEGESTOACCOUNT		0x13
#define LSA_LSARREMOVEPRIVILEGESFROMACCOUNT	0x14
#define LSA_LSARGETQUOTASFORACCOUNT		0x15
#define LSA_LSARSETQUOTASFORACCOUNT		0x16
#define LSA_LSARGETSYSTEMACCESSACCOUNT		0x17
#define LSA_LSARSETSYSTEMACCESSACCOUNT		0x18
#define LSA_LSAROPENTRUSTEDDOMAIN		0x19
#define LSA_LSARQUERYINFOTRUSTEDDOMAIN		0x1a
#define LSA_LSARSETINFORMATIONTRUSTEDDOMAIN	0x1b
#define LSA_LSAROPENSECRET			0x1c
#define LSA_LSARSETSECRET			0x1d
#define LSA_LSARQUERYSECRET			0x1e
#define LSA_LSARLOOKUPPRIVILEGEVALUE		0x1f
#define LSA_LSARLOOKUPPRIVILEGENAME		0x20
#define LSA_LSARLOOKUPPRIVILEGEDISPLAYNAME	0x21
#define LSA_LSARDELETEOBJECT			0x22
#define LSA_LSARENUMERATEACCOUNTSWITHUSERRIGHT	0x23
#define LSA_LSARENUMERATEACCOUNTRIGHTS		0x24
#define LSA_LSARADDACCOUNTRIGHTS		0x25
#define LSA_LSARREMOVEACCOUNTRIGHTS		0x26
#define LSA_LSARQUERYTRUSTEDDOMAININFO		0x27
#define LSA_LSARSETTRUSTEDDOMAININFO		0x28
#define LSA_LSARDELETETRUSTEDDOMAIN		0x29
#define LSA_LSARSTOREPRIVATEDATA		0x2a
#define LSA_LSARRETRIEVEPRIVATEDATA		0x2b
#define LSA_LSAROPENPOLICY2			0x2c
#define LSA_LSARGETUSERNAME			0x2d
#define LSA_LSARQUERYINFORMATIONPOLICY2		0x2e
#define LSA_LSARSETINFORMATIONPOLICY2		0x2f
#define LSA_LSARQUERYTRUSTEDDOMAININFOBYNAME	0x30
#define LSA_LSARSETTRUSTEDDOMAININFOBYNAME	0x31
#define LSA_LSARENUMERATETRUSTEDDOMAINSEX	0x32
#define LSA_LSARCREATETRUSTEDDOMAINEX		0x33
#define LSA_LSARCLOSETRUSTEDDOMAINEX		0x34
#define LSA_LSARQUERYDOMAININFORMATIONPOLICY	0x35
#define LSA_LSARSETDOMAININFORMATIONPOLICY	0x36
#define LSA_LSAROPENTRUSTEDDOMAINBYNAME		0x37
#define LSA_LSARTESTCALL			0x38
#define LSA_LSARLOOKUPSIDS2			0x39
#define LSA_LSARLOOKUPNAMES2			0x3a
#define LSA_LSARCREATETRUSTEDDOMAINEX2		0x3b
#define LSA_CREDRWRITE 				0x3c
#define LSA_CREDRREAD				0x3d
#define LSA_CREDRENUMERATE			0x3e
#define LSA_CREDRWRITEDOMAINCREDENTIALS		0x3f
#define LSA_CREDRREADDOMAINCREDENTIALS		0x40
#define LSA_CREDRDELETE				0x41
#define LSA_CREDRGETTARGETINFO			0x42
#define LSA_CREDRPROFILELOADED			0x43
#define LSA_LSARLOOKUPNAMES3			0x44
#define LSA_CREDRGETSESSIONTYPES 		0x45
#define LSA_LSARREGISTERAUDITEVENT		0x46
#define LSA_LSARGENAUDITEVENT			0x47
#define LSA_LSARUNREGISTERAUDITEVENT		0x48
#define LSA_LSARQUERYFORESTTRUSTINFORMATION	0x49
#define LSA_LSARSETFORESTTRUSTINFORMATION	0x4a
#define LSA_CREDRRENAME				0x4b
#define LSA_LSARLOOKUPSIDS3			0x4c
#define LSA_LSARLOOKUPNAMES4			0x4d
#define LSA_LSAROPENPOLICYSCE			0x4e
#define LSA_LSARADTREGISTERSECURITYEVENTSOURCE	0x4f
#define LSA_LSARADTUNREGISTERSECURITYEVENTSOURCE 0x50
#define LSA_LSARADTREPORTSECURITYEVENT		0x51

int
lsa_dissect_sec_desc_buf(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep, int dummy1, guint32 dummy2);
int
lsa_dissect_sec_desc_buf_data(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
			     guint8 *drep);
int
lsa_dissect_LSA_SECRET(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep);

int
lsa_dissect_DnsDomainInfo(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			guint8 *drep, int dummy1, guint32 dummy2);

/* Specific access rights */

#define POLICY_VIEW_LOCAL_INFORMATION    0x00000001
#define POLICY_VIEW_AUDIT_INFORMATION    0x00000002
#define POLICY_GET_PRIVATE_INFORMATION   0x00000004
#define POLICY_TRUST_ADMIN               0x00000008
#define POLICY_CREATE_ACCOUNT            0x00000010
#define POLICY_CREATE_SECRET             0x00000020
#define POLICY_CREATE_PRIVILEGE          0x00000040
#define POLICY_SET_DEFAULT_QUOTA_LIMITS  0x00000080
#define POLICY_SET_AUDIT_REQUIREMENTS    0x00000100
#define POLICY_AUDIT_LOG_ADMIN           0x00000200
#define POLICY_SERVER_ADMIN              0x00000400
#define POLICY_LOOKUP_NAMES              0x00000800

#endif /* packet-dcerpc-lsa.h */
