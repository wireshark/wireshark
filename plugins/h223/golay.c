/* $Id$
 *
 * Provides routines for encoding and decoding the extended Golay
 * (24,12,8) code.
 *
 * This implementation will detect up to 4 errors in a codeword (without
 * being able to correct them); it will correct up to 3 errors.
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include <glib.h>
#include "golay.h"


/* Encoding matrix, H

   These entries are formed from the matrix specified in H.223/B.3.2.1.3;
   it's first transposed so we have:

   [P1 ]   [111110010010]  [MC1 ]
   [P2 ]   [011111001001]  [MC2 ]
   [P3 ]   [110001110110]  [MC3 ]
   [P4 ]   [011000111011]  [MC4 ]
   [P5 ]   [110010001111]  [MPL1]
   [P6 ] = [100111010101]  [MPL2]
   [P7 ]   [101101111000]  [MPL3]
   [P8 ]   [010110111100]  [MPL4]
   [P9 ]   [001011011110]  [MPL5]
   [P10]   [000101101111]  [MPL6]
   [P11]   [111100100101]  [MPL7]
   [P12]   [101011100011]  [MPL8]

   So according to the equation, P1 = MC1+MC2+MC3+MC4+MPL1+MPL4+MPL7

   Looking down the first column, we see that if MC1 is set, we toggle bits
   1,3,5,6,7,11,12 of the parity: in binary, 110001110101 = 0xE3A

   Similarly, to calculate the inverse, we read across the top of the table and
   see that P1 is affected by bits MC1,MC2,MC3,MC4,MPL1,MPL4,MPL7: in binary,
   111110010010 = 0x49F.

   I've seen cunning implementations of this which only use one table. That
   technique doesn't seem to work with these numbers though.
*/

static const guint golay_encode_matrix[12] = {
    0xC75,
    0x49F,
    0xD4B,
    0x6E3,
    0x9B3,
    0xB66,
    0xECC,
    0x1ED,
    0x3DA,
    0x7B4,
    0xB1D,
    0xE3A,
};

static const guint golay_decode_matrix[12] = {
   0x49F,
   0x93E,
   0x6E3,
   0xDC6,
   0xF13,
   0xAB9,
   0x1ED,
   0x3DA,
   0x7B4,
   0xF68,
   0xA4F,
   0xC75,
};



/* Function to compute the Hamming weight of a 12-bit integer */
static guint weight12(guint vector)
{
    guint w=0;
    guint i;
    for( i=0; i<12; i++ )
	if( vector & 1<<i )
	    w++;
    return w;
}

/* returns the golay coding of the given 12-bit word */
static guint golay_coding(guint w)
{
    guint out=0;
    guint i;

    for( i = 0; i<12; i++ ) {
	if( w & 1<<i )
	    out ^= golay_encode_matrix[i];
    }
    return out;
}

/* encodes a 12-bit word to a 24-bit codeword */
guint32 golay_encode(guint w)
{
    return ((guint32)w) | ((guint32)golay_coding(w))<<12;
}



/* returns the golay coding of the given 12-bit word */
static guint golay_decoding(guint w)
{
    guint out=0;
    guint i;

    for( i = 0; i<12; i++ ) {
	if( w & 1<<(i) )
	    out ^= golay_decode_matrix[i];
    }
    return out;
}


/* return a mask showing the bits which are in error in a received
 * 24-bit codeword, or -1 if 4 errors were detected.
 */
gint32 golay_errors(guint32 codeword)
{
    guint received_data, received_parity;
    guint syndrome;
    guint w,i;
    guint inv_syndrome = 0;

    received_parity = (guint)(codeword>>12);
    received_data   = (guint)codeword & 0xfff;

    /* We use the C notation ^ for XOR to represent addition modulo 2.
     *
     * Model the received codeword (r) as the transmitted codeword (u)
     * plus an error vector (e).
     *
     *   r = e ^ u
     *
     * Then we calculate a syndrome (s):
     *
     *   s = r * H, where H = [ P   ], where I12 is the identity matrix
     *                        [ I12 ]
     *
     * (In other words, we calculate the parity check for the received
     * data bits, and add them to the received parity bits)
     */

    syndrome = received_parity ^ (golay_coding(received_data));
    w = weight12(syndrome);
    
    /*
     * The properties of the golay code are such that the Hamming distance (ie,
     * the minimum distance between codewords) is 8; that means that one bit of
     * error in the data bits will cause 7 errors in the parity bits.
     *
     * In particular, if we find 3 or fewer errors in the parity bits, either:
     *  - there are no errors in the data bits, or
     *  - there are at least 5 errors in the data bits
     * we hope for the former (we don't profess to deal with the
     * latter).
     */
    if( w <= 3 ) {
	return ((gint32) syndrome)<<12;
    }
    
    /* the next thing to try is one error in the data bits.
     * we try each bit in turn and see if an error in that bit would have given
     * us anything like the parity bits we got. At this point, we tolerate two
     * errors in the parity bits, but three or more errors would give a total
     * error weight of 4 or more, which means it's actually uncorrectable or
     * closer to another codeword. */
     
    for( i = 0; i<12; i++ ) {
	guint error = 1<<i;
	guint coding_error = golay_encode_matrix[i];
	if( weight12(syndrome^coding_error) <= 2 ) {
	    return (gint32)((((guint32)(syndrome^coding_error))<<12) | (guint32)error) ;
	}
    }

    /* okay then, let's see whether the parity bits are error free, and all the
     * errors are in the data bits. model this as follows:
     *
     * [r | pr] = [u | pu] + [e | 0]
     *
     * pr = pu
     * pu = H * u => u = H' * pu = H' * pr , where H' is inverse of H
     *
     * we already have s = H*r + pr, so pr = s - H*r = s ^ H*r
     * e = u ^ r
     *   = (H' * ( s ^ H*r )) ^ r
     *   = H'*s ^ r ^ r
     *   = H'*s
     *
     * Once again, we accept up to three error bits...
     */

    inv_syndrome = golay_decoding(syndrome);
    w = weight12(inv_syndrome);
    if( w <=3 ) {
	return (gint32)inv_syndrome;
    }

    /* Final shot: try with 2 errors in the data bits, and 1 in the parity
     * bits; as before we try each of the bits in the parity in turn */
    for( i = 0; i<12; i++ ) {
	guint error = 1<<i;
	guint coding_error = golay_decode_matrix[i];
	if( weight12(inv_syndrome^coding_error) <= 2 ) {
	    guint32 error_word = ((guint32)(inv_syndrome^coding_error)) | ((guint32)error)<<12;
	    return (gint32)error_word;
	}
    }

    /* uncorrectable error */
    return -1;
}
    


/* decode a received codeword. Up to 3 errors are corrected for; 4
   errors are detected as uncorrectable (return -1); 5 or more errors
   cause an incorrect correction.
*/
gint golay_decode(guint32 w)
{
    guint data = (guint)w & 0xfff;
    gint32 errors = golay_errors(w);
    guint data_errors;
    
    if( errors == -1 )
	return -1;
    data_errors = (guint)errors & 0xfff;
    return (gint)(data ^ data_errors);
}
