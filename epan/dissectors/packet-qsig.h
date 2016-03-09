/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-qsig.h                                                              */
/* asn2wrs.py -c ./qsig.cnf -s ./packet-qsig-template -D . -O ../.. General-Error-List.asn qsig-gf-ext.asn qsig-gf-gp.asn qsig-gf-ade.asn QSIG-NA.asn QSIG-CF.asn QSIG-PR.asn QSIG-CT.asn QSIG-CC.asn QSIG-CO.asn QSIG-DND.asn QSIG-CI.asn QSIG-AOC.asn QSIG-RE.asn SYNC-SIG.asn QSIG-CINT.asn QSIG-CMN.asn QSIG-CPI.asn QSIG-PUMR.asn QSIG-PUMCH.asn QSIG-SSCT.asn QSIG-WTMLR.asn QSIG-WTMCH.asn QSIG-WTMAU.asn QSIG-SD.asn QSIG-CIDL.asn QSIG-SMS.asn QSIG-MCR.asn QSIG-MCM.asn QSIG-MID.asn */

/* Input file: packet-qsig-template.h */

#line 1 "./asn1/qsig/packet-qsig-template.h"
/* packet-qsig.h
 * Routines for QSIG packet dissection
 * 2007  Tomas Kukosa
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

#ifndef PACKET_QSIG_H
#define PACKET_QSIG_H


/*--- Included file: packet-qsig-exp.h ---*/
#line 1 "./asn1/qsig/packet-qsig-exp.h"

/* --- Module General-Error-List --- --- ---                                  */


/* --- Modules Manufacturer-specific-service-extension-class-asn1-97 PSS1-generic-parameters-definition-asn1-97 Addressing-Data-Elements-asn1-97 --- --- --- */


/* --- Module Name-Operations-asn1-97 --- --- ---                             */


static const value_string qsig_na_Name_vals[] = {
  {   0, "namePresentationAllowed" },
  {   1, "namePresentationRestricted" },
  {   2, "nameNotAvailable" },
  { 0, NULL }
};
WS_DLL_PUBLIC int dissect_qsig_na_Name(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* --- Module Call-Diversion-Operations-asn1-97 --- --- ---                   */


/* --- Module Path-Replacement-Operations-asn1-97 --- --- ---                 */


/* --- Module Call-Transfer-Operations-asn1-97 --- --- ---                    */


/* --- Module SS-CC-Operations-asn1-97 --- --- ---                            */


/* --- Module Call-Offer-Operations-asn1-97 --- --- ---                       */


/* --- Module Do-Not-Disturb-Operations-asn1-97 --- --- ---                   */


/* --- Module Call-Intrusion-Operations-asn1-97 --- --- ---                   */


/* --- Module SS-AOC-Operations-asn1-97 --- --- ---                           */


/* --- Module Recall-Operations-asn1-97 --- --- ---                           */


/* --- Module Synchronization-Operations-asn1-97 --- --- ---                  */


/* --- Module Call-Interception-Operations-asn1-97 --- --- ---                */


/* --- Module Common-Information-Operations-asn1-97 --- --- ---               */


/* --- Module Call-Interruption-Operations-asn1-97 --- --- ---                */


/* --- Module PUM-Registration-Operations-asn1-97 --- --- ---                 */


/* --- Module Private-User-Mobility-Call-Handling-Operations-asn1-97 --- --- --- */


/* --- Module Single-Step-Call-Transfer-Operations-asn1-97 --- --- ---        */


/* --- Module WTM-Location-Registration-Operations-asn1-97 --- --- ---        */


/* --- Module Wireless-Terminal-Call-Handling-Operations-asn1-97 --- --- ---  */


/* --- Module WTM-Authentication-Operations-asn1-97 --- --- ---               */


/* --- Module SS-SD-Operations-asn1-97 --- --- ---                            */


/* --- Module Call-Identification-and-Call-Linkage-Operations-asn1-97 --- --- --- */


/* --- Module Short-Message-Service-Operations-asn1-97 --- --- ---            */


/* --- Module SS-MCR-Operations-asn97 --- --- ---                             */


/* --- Module SS-MCM-Operations-asn1-97 --- --- ---                           */


/* --- Module SS-MID-Operations-asn1-97 --- --- ---                           */


/*--- End of included file: packet-qsig-exp.h ---*/
#line 28 "./asn1/qsig/packet-qsig-template.h"

#endif  /* PACKET_QSIG_H */

