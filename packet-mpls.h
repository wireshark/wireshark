/**********************************************************************
 *
 * packet-mpls.h
 *
 * (C) Ashok Narayanan <ashokn@cisco.com>
 *
 * $Id: packet-mpls.h,v 1.1 2000/03/09 18:31:51 ashokn Exp $
 *
 * For license details, see the COPYING file with this distribution
 *
 **********************************************************************/

void dissect_mpls(const u_char *, int, frame_data *, proto_tree *);
