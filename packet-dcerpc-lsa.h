/* packet-dcerpc-lsa.h
 * Routines for SMB \PIPE\lsarpc packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-dcerpc-lsa.h,v 1.5 2002/06/18 13:18:30 sahlberg Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#define LSA_LSACLOSE	0x00
#define LSA_LSADELETE	0x01
#define LSA_LSAENUMERATEPRIVILEGES	0x02
#define LSA_LSAQUERYSECURITYOBJECT	0x03
#define LSA_LSASETSECURITYOBJECT	0x04
#define LSA_LSACHANGEPASSWORD	0x05
#define LSA_LSAOPENPOLICY	0x06
#define LSA_LSAQUERYINFORMATIONPOLICY	0x07
#define LSA_LSASETINFORMATIONPOLICY	0x08
#define LSA_LSACLEARAUDITLOG	0x09
#define LSA_LSACREATEACCOUNT	0x0a
#define LSA_LSAENUMERATEACCOUNTS	0x0b
#define LSA_LSACREATETRUSTEDDOMAIN	0x0c
#define LSA_LSAENUMERATETRUSTEDDOMAINS	0x0d
#define LSA_LSALOOKUPNAMES	0x0e
#define LSA_LSALOOKUPSIDS	0x0f
#define LSA_LSACREATESECRET	0x10
#define LSA_LSAOPENACCOUNT	0x11
#define LSA_LSAENUMERATEPRIVILEGESACCOUNT	0x12
#define LSA_LSAADDPRIVILEGESTOACCOUNT	0x13
#define LSA_LSAREMOVEPRIVILEGESFROMACCOUNT	0x14
#define LSA_LSAGETQUOTASFORACCOUNT	0x15
#define LSA_LSASETQUOTASFORACCOUNT	0x16
#define LSA_LSAGETSYSTEMACCESSACCOUNT	0x17
#define LSA_LSASETSYSTEMACCESSACCOUNT	0x18
#define LSA_LSAOPENTRUSTEDDOMAIN	0x19
#define LSA_LSAQUERYINFOTRUSTEDDOMAIN	0x1a
#define LSA_LSASETINFORMATIONTRUSTEDDOMAIN	0x1b
#define LSA_LSAOPENSECRET	0x1c
#define LSA_LSASETSECRET	0x1d
#define LSA_LSAQUERYSECRET	0x1e
#define LSA_LSALOOKUPPRIVILEGEVALUE	0x1f
#define LSA_LSALOOKUPPRIVILEGENAME	0x20
#define LSA_LSALOOKUPPRIVILEGEDISPLAYNAME	0x21
#define LSA_LSADELETEOBJECT	0x22
#define LSA_LSAENUMERATEACCOUNTSWITHUSERRIGHT	0x23
#define LSA_LSAENUMERATEACCOUNTRIGHTS	0x24
#define LSA_LSAADDACCOUNTRIGHTS	0x25
#define LSA_LSAREMOVEACCOUNTRIGHTS	0x26
#define LSA_LSAQUERYTRUSTEDDOMAININFO	0x27
#define LSA_LSASETTRUSTEDDOMAININFO	0x28
#define LSA_LSADELETETRUSTEDDOMAIN	0x29
#define LSA_LSASTOREPRIVATEDATA	0x2a
#define LSA_LSARETRIEVEPRIVATEDATA	0x2b
#define LSA_LSAOPENPOLICY2	0x2c
#define LSA_LSAGETUSERNAME	0x2d
#define LSA_LSAFUNCTION_2E	0x2e
#define LSA_LSAFUNCTION_2F	0x2f
#define LSA_LSAQUERYTRUSTEDDOMAININFOBYNAME	0x30
#define LSA_LSASETTRUSTEDDOMAININFOBYNAME	0x31
#define LSA_LSAENUMERATETRUSTEDDOMAINSEX	0x32
#define LSA_LSACREATETRUSTEDDOMAINEX	0x33
#define LSA_LSACLOSETRUSTEDDOMAINEX	0x34
#define LSA_LSAQUERYDOMAININFORMATIONPOLICY	0x35
#define LSA_LSASETDOMAININFORMATIONPOLICY	0x36
#define LSA_LSAOPENTRUSTEDDOMAINBYNAME	0x37
#define LSA_LSAFUNCTION_38	0x38
#define LSA_LSALOOKUPSIDS2	0x39
#define LSA_LSALOOKUPNAMES2	0x3a
#define LSA_LSAFUNCTION_3B	0x3b

int
lsa_dissect_LSA_SECURITY_DESCRIPTOR(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree,
                             char *drep);
int
lsa_dissect_LSA_SECURITY_DESCRIPTOR_data(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree,
			     char *drep);
int
lsa_dissect_LSA_SECRET(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			char *drep);

#endif /* packet-dcerpc-lsa.h */
