/**********************************************************************
 *
 * packet-rsvp.h
 *
 * (C) Ashok Narayanan <ashokn@cisco.com>
 *
 * $Id: packet-rsvp.h,v 1.8 2000/02/15 21:03:03 gram Exp $
 *
 * For license details, see the COPYING file with this distribution
 *
 **********************************************************************/

void dissect_rsvp(const u_char *, int, frame_data *, proto_tree *);
