/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-gdt.h                                                               */
/* asn2wrs.py -b -q -L -p gdt -c ./gdt.cnf -s ./packet-gdt-template -D . -O ../.. gdt.asn */

/* packet-gdt-template.h
 *
 * Copyright 2022, Damir Franusic <damir.franusic@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef PACKET_GDT_H
#define PACKET_GDT_H

void proto_register_gdt(void);
void proto_reg_handoff_gdt(void);

#endif  /* PACKET_GDT_H */
