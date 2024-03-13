/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-q932.h                                                              */
/* asn2wrs.py -b -q -L -p q932 -c ./q932.cnf -s ./packet-q932-template -D . -O ../.. Addressing-Data-Elements.asn Network-Facility-Extension.asn Network-Protocol-Profile-component.asn Interpretation-component.asn */

/* packet-q932.h
 * Routines for Q.932 packet dissection
 * 2007  Tomas Kukosa
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_Q932_H
#define PACKET_Q932_H

WS_DLL_PUBLIC const value_string q932_PresentedAddressScreened_vals[];
WS_DLL_PUBLIC const value_string q932_PresentedAddressUnscreened_vals[];
WS_DLL_PUBLIC const value_string q932_PresentedNumberScreened_vals[];
WS_DLL_PUBLIC const value_string q932_PresentedNumberUnscreened_vals[];
WS_DLL_PUBLIC const value_string q932_PartyNumber_vals[];
WS_DLL_PUBLIC const value_string q932_PartySubaddress_vals[];
WS_DLL_PUBLIC const value_string q932_ScreeningIndicator_vals[];
WS_DLL_PUBLIC int dissect_q932_PresentedAddressScreened(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
WS_DLL_PUBLIC int dissect_q932_PresentedAddressUnscreened(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
WS_DLL_PUBLIC int dissect_q932_PresentedNumberScreened(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
WS_DLL_PUBLIC int dissect_q932_PresentedNumberUnscreened(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
WS_DLL_PUBLIC int dissect_q932_Address(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
WS_DLL_PUBLIC int dissect_q932_PartyNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
WS_DLL_PUBLIC int dissect_q932_PartySubaddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
WS_DLL_PUBLIC int dissect_q932_ScreeningIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
WS_DLL_PUBLIC int dissect_q932_PresentationAllowedIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

#endif  /* PACKET_Q932_H */

