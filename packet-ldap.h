/* packet-ldap.h
 *
 * $Id: packet-ldap.h,v 1.2 2000/03/28 07:12:23 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#define LBER_BOOLEAN            0x01L
#define LBER_INTEGER            0x02L
#define LBER_BITSTRING          0x03L
#define LBER_OCTETSTRING        0x04L
#define LBER_NULL               0x05L
#define LBER_ENUMERATED         0x0aL
#define LBER_SEQUENCE           0x30L   /* constructed */
#define LBER_SET                0x31L   /* constructed */
#define OLD_LBER_SEQUENCE       0x10L   /* w/o constructed bit - broken */
#define OLD_LBER_SET            0x11L   /* w/o constructed bit - broken */

#define LDAP_REQ_BIND                   0x60L   /* application + constructed */
#define LDAP_REQ_UNBIND                 0x42L   /* application + primitive   */
#define LDAP_REQ_SEARCH                 0x63L   /* application + constructed */
#define LDAP_REQ_MODIFY                 0x66L   /* application + constructed */
#define LDAP_REQ_ADD                    0x68L   /* application + constructed */
#define LDAP_REQ_DELETE                 0x4aL   /* application + primitive   */
#define LDAP_REQ_MODRDN                 0x6cL   /* application + constructed */
#define LDAP_REQ_COMPARE                0x6eL   /* application + constructed */
#define LDAP_REQ_ABANDON                0x50L   /* application + primitive   */

#define LDAP_REQ_UNBIND_30              0x62L
#define LDAP_REQ_DELETE_30              0x6aL
#define LDAP_REQ_ABANDON_30             0x70L

#define OLD_LDAP_REQ_BIND               0x00L
#define OLD_LDAP_REQ_UNBIND             0x02L
#define OLD_LDAP_REQ_SEARCH             0x03L
#define OLD_LDAP_REQ_MODIFY             0x06L
#define OLD_LDAP_REQ_ADD                0x08L
#define OLD_LDAP_REQ_DELETE             0x0aL
#define OLD_LDAP_REQ_MODRDN             0x0cL
#define OLD_LDAP_REQ_COMPARE            0x0eL
#define OLD_LDAP_REQ_ABANDON            0x10L

#define LDAP_RES_BIND                   0x61L   /* application + constructed */
#define LDAP_RES_SEARCH_ENTRY           0x64L   /* application + constructed */
#define LDAP_RES_SEARCH_RESULT          0x65L   /* application + constructed */
#define LDAP_RES_MODIFY                 0x67L   /* application + constructed */
#define LDAP_RES_ADD                    0x69L   /* application + constructed */
#define LDAP_RES_DELETE                 0x6bL   /* application + constructed */
#define LDAP_RES_MODRDN                 0x6dL   /* application + constructed */
#define LDAP_RES_COMPARE                0x6fL   /* application + constructed */

#define OLD_LDAP_RES_BIND               0x01L
#define OLD_LDAP_RES_SEARCH_ENTRY       0x04L
#define OLD_LDAP_RES_SEARCH_RESULT      0x05L
#define OLD_LDAP_RES_MODIFY             0x07L
#define OLD_LDAP_RES_ADD                0x09L
#define OLD_LDAP_RES_DELETE             0x0bL
#define OLD_LDAP_RES_MODRDN             0x0dL
#define OLD_LDAP_RES_COMPARE            0x0fL

#define LDAP_AUTH_NONE          0x00L   /* no authentication              */
#define LDAP_AUTH_SIMPLE        0x80L   /* context specific + primitive   */
#define LDAP_AUTH_KRBV4         0xffL   /* means do both of the following */
#define LDAP_AUTH_KRBV41        0x81L   /* context specific + primitive   */
#define LDAP_AUTH_KRBV42        0x82L   /* context specific + primitive   */

#define LDAP_AUTH_SIMPLE_30     0xa0L   /* context specific + constructed */
#define LDAP_AUTH_KRBV41_30     0xa1L   /* context specific + constructed */
#define LDAP_AUTH_KRBV42_30     0xa2L   /* context specific + constructed */

#define OLD_LDAP_AUTH_SIMPLE    0x00L
#define OLD_LDAP_AUTH_KRBV4     0x01L
#define OLD_LDAP_AUTH_KRBV42    0x02L

/* filter types */
#define LDAP_FILTER_AND         0xa0L   /* context specific + constructed */
#define LDAP_FILTER_OR          0xa1L   /* context specific + constructed */
#define LDAP_FILTER_NOT         0xa2L   /* context specific + constructed */
#define LDAP_FILTER_EQUALITY    0xa3L   /* context specific + constructed */
#define LDAP_FILTER_SUBSTRINGS  0xa4L   /* context specific + constructed */
#define LDAP_FILTER_GE          0xa5L   /* context specific + constructed */
#define LDAP_FILTER_LE          0xa6L   /* context specific + constructed */
#define LDAP_FILTER_PRESENT     0x87L   /* context specific + primitive   */
#define LDAP_FILTER_APPROX      0xa8L   /* context specific + constructed */

/* 3.0 compatibility filter types */
#define LDAP_FILTER_PRESENT_30  0xa7L   /* context specific + constructed */

#define LDAP_MOD_ADD            0x00
#define LDAP_MOD_DELETE         0x01
#define LDAP_MOD_REPLACE        0x02



void dissect_ldap(const u_char *, int, frame_data *, proto_tree *);
