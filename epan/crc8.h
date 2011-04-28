/* crc8.h
 *
 * Checks the checksum (FCS) of the 3G TS 27.010 Multiplexing protocol.
 * The algorithm to check the FCS is described in "3G TS 27.010 V2.0.0 (1999-06)"
 * See: www.3gpp.org/ftp/tsg_t/TSG_T/TSGT_04/docs/PDFs/TP-99119.pdf
 * or: http://www.3gpp.org/ftp/Specs/html-info/27010.htm
 *
 * Polynom: (x^8 + x^2 + x^1 + 1)
 *
 * 2011 Hans-Christoph Schemmel <hans-christoph.schemmel[AT]cinterion.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */


/**
 * Check the final crc value(Receiver code)
 *
 * \param p The tv buffer containing the data.
 * \param len Number of bytes in the message.
 * \param offset Offset in the message.
 * \param received_fcs The received FCS.
 * \return     Returns TRUE if the checksum is correct, FALSE if it is not correct
 *****************************************************************************/
extern gboolean check_fcs(tvbuff_t *p, guint8 len, guint8 offset, guint8 received_fcs);
