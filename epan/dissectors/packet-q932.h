/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-q932.h                                                              */
/* ../../tools/asn2wrs.py -e -b -p q932 -c ./q932.cnf -s ./packet-q932-template -D . Addressing-Data-Elements.asn Network-Facility-Extension.asn Network-Protocol-Profile-component.asn Interpretation-component.asn */

/* Input file: packet-q932-template.h */

#line 1 "../../asn1/q932/packet-q932-template.h"
/* packet-q932.h
 * Routines for Q.932 packet dissection
 * 2007  Tomas Kukosa
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

#ifndef PACKET_Q932_H
#define PACKET_Q932_H


/*--- Included file: packet-q932-exp.h ---*/
#line 1 "../../asn1/q932/packet-q932-exp.h"

static const value_string q932_PresentedAddressScreened_vals[] = {
  {   0, "presentationAlIowedAddress" },
  {   1, "presentationRestricted" },
  {   2, "numberNotAvailableDueTolnterworking" },
  {   3, "presentationRestrictedAddress" },
  { 0, NULL }
};

static const value_string q932_PresentedAddressUnscreened_vals[] = {
  {   0, "presentationAllowedAddress" },
  {   1, "presentationRestricted" },
  {   2, "numberNotAvailableDueTolnterworking" },
  {   3, "presentationRestrictedAddress" },
  { 0, NULL }
};

static const value_string q932_PresentedNumberScreened_vals[] = {
  {   0, "presentationAllowedNumber" },
  {   1, "presentationRestricted" },
  {   2, "numberNotAvailableDueToInterworking" },
  {   3, "presentationRestrictedNumber" },
  { 0, NULL }
};

static const value_string q932_PresentedNumberUnscreened_vals[] = {
  {   0, "presentationAllowedNumber" },
  {   1, "presentationRestricted" },
  {   2, "numberNotAvailableDueToInterworking" },
  {   3, "presentationRestrictedNumber" },
  { 0, NULL }
};

static const value_string q932_PartyNumber_vals[] = {
  {   0, "unknownPartyNumber" },
  {   1, "publicPartyNumber" },
  {   2, "nsapEncodedNumber" },
  {   3, "dataPartyNumber" },
  {   4, "telexPartyNumber" },
  {   5, "privatePartyNumber" },
  {   8, "nationalStandardPartyNumber" },
  { 0, NULL }
};

static const value_string q932_PartySubaddress_vals[] = {
  {   0, "userSpecifiedSubaddress" },
  {   1, "nSAPSubaddress" },
  { 0, NULL }
};

static const value_string q932_ScreeningIndicator_vals[] = {
  {   0, "userProvidedNotScreened" },
  {   1, "userProvidedVerifiedAndPassed" },
  {   2, "userProvidedVerifiedAndFailed" },
  {   3, "networkProvided" },
  { 0, NULL }
};
extern int dissect_q932_PresentedAddressScreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
extern int dissect_q932_PresentedAddressUnscreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
extern int dissect_q932_PresentedNumberScreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
extern int dissect_q932_PresentedNumberUnscreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
extern int dissect_q932_Address(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
extern int dissect_q932_PartyNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
extern int dissect_q932_PartySubaddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
extern int dissect_q932_ScreeningIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
extern int dissect_q932_PresentationAllowedIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/*--- End of included file: packet-q932-exp.h ---*/
#line 30 "../../asn1/q932/packet-q932-template.h"

#endif  /* PACKET_Q932_H */

