/** @file
 *
 * Checks the checksum (FCS) of the 3G TS 27.010 Multiplexing protocol.
 * The algorithm to check the FCS is described in "3G TS 27.010 V2.0.0 (1999-06)"
 * See: www.3gpp.org/ftp/tsg_t/TSG_T/TSGT_04/docs/PDFs/TP-99119.pdf
 * or: http://www.3gpp.org/ftp/Specs/html-info/27010.htm
 *
 * Polynom: (x^8 + x^2 + x^1 + 1)
 *
 * 2011 Hans-Christoph Schemmel <hans-christoph.schemmel[AT]cinterion.com>
 * 2014 Philip Rosenberg-Watt <p.rosenberg-watt[at]cablelabs.com>
 *  + Added CRC-8 for IEEE 802.3 EPON, with shift register initialized to 0x00
 *    See IEEE Std 802.3-2012 Section 5, Clause 65.1.3.2.3.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


/**
 * Check the final crc value(Receiver code)
 *
 * \param p The tv buffer containing the data.
 * \param len Number of bytes in the message.
 * \param offset Offset in the message.
 * \param received_fcs The received FCS.
 * \return     Returns true if the checksum is correct, false if it is not correct
 *****************************************************************************/

#ifndef __CRC8_TVB_H__
#define __CRC8_TVB_H__

extern bool check_fcs(tvbuff_t *p, uint8_t len, uint8_t offset, uint8_t received_fcs);
extern uint8_t get_crc8_ieee8023_epon(tvbuff_t *p, uint8_t len, uint8_t offset);

#endif /* __CRC8_TVB_H__ */
