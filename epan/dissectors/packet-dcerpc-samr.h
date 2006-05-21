/* packet-dcerpc-samr.h
 * Routines for SMB \PIPE\samr packet disassembly
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

#ifndef __PACKET_DCERPC_SAMR_H
#define __PACKET_DCERPC_SAMR_H

/* Functions available on the SAMR pipe.  From Samba, include/rpc_samr.h */

#define SAMR_CONNECT                		0x00
#define SAMR_CLOSE_HND              		0x01
#define SAMR_SET_SEC_OBJECT         		0x02
#define SAMR_QUERY_SEC_OBJECT       		0x03
#define SAMR_SHUTDOWN_SAM_SERVER    		0x04
#define SAMR_LOOKUP_DOMAIN          		0x05
#define SAMR_ENUM_DOMAINS           		0x06
#define SAMR_OPEN_DOMAIN            		0x07
#define SAMR_QUERY_DOMAIN_INFO      		0x08
#define SAMR_SET_DOMAIN_INFO        		0x09
#define SAMR_CREATE_DOM_GROUP       		0x0a
#define SAMR_ENUM_DOM_GROUPS   			0x0b
#define SAMR_CREATE_USER_IN_DOMAIN 		0x0c
#define SAMR_ENUM_DOM_USERS    			0x0d
#define SAMR_CREATE_DOM_ALIAS  			0x0e
#define SAMR_ENUM_DOM_ALIASES  			0x0f
#define SAMR_GET_ALIAS_MEMBERSHIP 		0x10
#define SAMR_LOOKUP_NAMES      			0x11
#define SAMR_LOOKUP_RIDS       			0x12
#define SAMR_OPEN_GROUP        			0x13
#define SAMR_QUERY_GROUPINFO   			0x14
#define SAMR_SET_GROUPINFO     			0x15
#define SAMR_ADD_GROUPMEM      			0x16
#define SAMR_DELETE_DOM_GROUP  			0x17
#define SAMR_DEL_GROUPMEM      			0x18
#define SAMR_QUERY_GROUPMEM    			0x19
#define SAMR_SET_MEMBER_ATTRIBUTES_OF_GROUP	0x1a
#define SAMR_OPEN_ALIAS        			0x1b
#define SAMR_QUERY_ALIASINFO   			0x1c
#define SAMR_SET_ALIASINFO     			0x1d
#define SAMR_DELETE_DOM_ALIAS  			0x1e
#define SAMR_ADD_ALIASMEM      			0x1f
#define SAMR_DEL_ALIASMEM      			0x20
#define SAMR_GET_MEMBERS_IN_ALIAS   		0x21
#define SAMR_OPEN_USER         			0x22
#define SAMR_DELETE_DOM_USER   			0x23
#define SAMR_QUERY_USERINFO    			0x24
#define SAMR_SET_USERINFO     			0x25
#define SAMR_CHANGE_PASSWORD_USER  		0x26
#define SAMR_GET_GROUPS_FOR_USER  		0x27
#define SAMR_QUERY_DISPINFO    			0x28
#define SAMR_GET_DISPLAY_ENUMERATION_INDEX     	0x29
#define SAMR_TEST_PRIVATE_FUNCTIONS_DOMAIN     	0x2a
#define SAMR_TEST_PRIVATE_FUNCTIONS_USER        0x2b
#define SAMR_GET_USRDOM_PWINFO 			0x2c
#define SAMR_REMOVE_MEMBER_FROM_FOREIGN_DOMAIN 	0x2d
#define SAMR_QUERY_INFORMATION_DOMAIN2    	0x2e
#define SAMR_QUERY_INFORMATION_USER2        	0x2f
#define SAMR_QUERY_DISPINFO2   			0x30
#define SAMR_GET_DISPLAY_ENUMERATION_INDEX2 	0x31
#define SAMR_CREATE_USER2_IN_DOMAIN       	0x32
#define SAMR_QUERY_DISPINFO3   			0x33
#define SAMR_ADD_MULTIPLE_MEMBERS_TO_ALIAS 	0x34
#define SAMR_REMOVE_MULTIPLE_MEMBERS_FROM_ALIAS 0x35
#define SAMR_OEM_CHANGE_PASSWORD_USER2 		0x36
#define SAMR_UNICODE_CHANGE_PASSWORD_USER2	0x37
#define SAMR_GET_DOM_PWINFO			0x38
#define SAMR_CONNECT2          			0x39
#define SAMR_SET_USERINFO2      		0x3a
#define SAMR_SET_BOOT_KEY_INFORMATION 		0x3b
#define SAMR_GET_BOOT_KEY_INFORMATION	       	0x3c
#define SAMR_CONNECT3          			0x3d
#define SAMR_CONNECT4          			0x3e
#define SAMR_UNICODE_CHANGE_PASSWORD_USER3 	0x3f
#define SAMR_CONNECT5				0x40	
#define SAMR_RID_TO_SID				0x41
#define SAMR_SET_DSRM_PASSWORD			0x42
#define SAMR_VALIDATE_PASSWORD			0x43

/* Specific access rights */

#define SAMR_ACCESS_CONNECT_TO_SERVER   0x00000001
#define SAMR_ACCESS_SHUTDOWN_SERVER     0x00000002
#define SAMR_ACCESS_INITIALIZE_SERVER   0x00000004
#define SAMR_ACCESS_CREATE_DOMAIN       0x00000008
#define SAMR_ACCESS_ENUM_DOMAINS        0x00000010
#define SAMR_ACCESS_OPEN_DOMAIN         0x00000020

#define DOMAIN_ACCESS_LOOKUP_INFO_1  0x00000001
#define DOMAIN_ACCESS_SET_INFO_1     0x00000002
#define DOMAIN_ACCESS_LOOKUP_INFO_2  0x00000004
#define DOMAIN_ACCESS_SET_INFO_2     0x00000008
#define DOMAIN_ACCESS_CREATE_USER    0x00000010
#define DOMAIN_ACCESS_CREATE_GROUP   0x00000020
#define DOMAIN_ACCESS_CREATE_ALIAS   0x00000040
#define DOMAIN_ACCESS_LOOKUP_ALIAS   0x00000080
#define DOMAIN_ACCESS_ENUM_ACCOUNTS  0x00000100
#define DOMAIN_ACCESS_OPEN_ACCOUNT   0x00000200
#define DOMAIN_ACCESS_SET_INFO_3     0x00000400

#define USER_ACCESS_GET_NAME_ETC             0x00000001
#define USER_ACCESS_GET_LOCALE               0x00000002
#define USER_ACCESS_SET_LOC_COM              0x00000004
#define USER_ACCESS_GET_LOGONINFO            0x00000008
#define USER_ACCESS_GET_ATTRIBUTES           0x00000010
#define USER_ACCESS_SET_ATTRIBUTES           0x00000020
#define USER_ACCESS_CHANGE_PASSWORD          0x00000040
#define USER_ACCESS_SET_PASSWORD             0x00000080
#define USER_ACCESS_GET_GROUPS               0x00000100
#define USER_ACCESS_GET_GROUP_MEMBERSHIP     0x00000200
#define USER_ACCESS_CHANGE_GROUP_MEMBERSHIP  0x00000400

#define ALIAS_ACCESS_ADD_MEMBER      0x00000001
#define ALIAS_ACCESS_REMOVE_MEMBER   0x00000002
#define ALIAS_ACCESS_GET_MEMBERS     0x00000004
#define ALIAS_ACCESS_LOOKUP_INFO     0x00000008
#define ALIAS_ACCESS_SET_INFO        0x00000010

#define GROUP_ACCESS_LOOKUP_INFO     0x00000001
#define GROUP_ACCESS_SET_INFO        0x00000002
#define GROUP_ACCESS_ADD_MEMBER      0x00000004
#define GROUP_ACCESS_REMOVE_MEMBER   0x00000008
#define GROUP_ACCESS_GET_MEMBERS     0x00000010

tvbuff_t *decrypt_tvb_using_nt_password(packet_info *pinfo, tvbuff_t *tvb, int offset, int len);

#endif /* packet-dcerpc-samr.h */
