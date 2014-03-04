/* Routines for UMTS RLC disassembly
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

#ifndef PACKET_RLC_H
#define PACKET_RLC_H

/* Do not change enum order and append only to keep
   backward compatibility with UDP framing format */
enum rlc_mode {
	RLC_TM,
	RLC_UM,
	RLC_AM,
	RLC_UNKNOWN_MODE
};

/* Do not change enum order and append only to keep
   backward compatibility with UDP framing format */
enum rlc_li_size {
	RLC_LI_VARIABLE,
	RLC_LI_7BITS,
	RLC_LI_15BITS
};

#define MAX_RLC_CHANS 64
typedef struct rlc_info
{
	guint32 urnti[MAX_RLC_CHANS];
	guint8 mode[MAX_RLC_CHANS];
	guint8 rbid[MAX_RLC_CHANS];
	enum rlc_li_size li_size[MAX_RLC_CHANS];
	gboolean ciphered[MAX_RLC_CHANS];
	gboolean deciphered[MAX_RLC_CHANS];
} rlc_info;

/* Reset the specified channel's reassembly data, useful for when a sequence
 * resets on transport channel swap. */
void rlc_reset_channel(enum rlc_mode mode, guint8 rbid, guint8 dir, guint32 urnti);

/* Tells other functions if this packet is ciphered or not */
gboolean rlc_is_ciphered(packet_info * pinfo);

/*****************************************************************/
/* UDP framing format                                            */
/* -----------------------                                       */
/* Several people have asked about dissecting RLC by framing     */
/* PDUs over IP.  A suggested format over UDP has been defined   */
/* and implemented by this dissector, using the definitions      */
/* below. A link to an example program showing you how to encode */
/* these headers and send RLC PDUs on a UDP socket is provided   */
/* at http://wiki.wireshark.org/RLC                              */
/*                                                               */
/* A heuristic dissecter (enabled by a preference) will          */
/* recognise a signature at the beginning of these frames.       */
/* Until someone is using this format, suggestions for changes   */
/* are welcome.                                                  */
/*****************************************************************/


/* Signature.  Rather than try to define a port for this, or make the
   port number a preference, frames will start with this string (with no
   terminating NULL */
#define RLC_START_STRING "umts-rlc"

/* Conditional fields. The channel type or RLC mode should be present.
   If the channel type is present, the RLC mode will be ignored.
   If none of them is present, the decoding will be skipped.
   The RLC mode tag uses the values from the rlc_mode enum. */

#define UMTS_CHANNEL_TYPE_UNSPECIFIED 0
#define UMTS_CHANNEL_TYPE_PCCH 1
#define UMTS_CHANNEL_TYPE_CCCH 2
#define UMTS_CHANNEL_TYPE_DCCH 3
#define UMTS_CHANNEL_TYPE_PS_DTCH 4
#define UMTS_CHANNEL_TYPE_CTCH 5
#define UMTS_CHANNEL_TYPE_BCCH 6

#define RLC_CHANNEL_TYPE_TAG    0x02
/* 1 byte */

#define RLC_MODE_TAG            0x03
/* 1 byte, enum rlc_mode value */

/* Optional fields. Attaching this info to frames will allow you
   to show you display/filter/plot/add-custom-columns on these fields, so should
   be added if available.
   The format is to have the tag, followed by the value (there is no length field,
   it's implicit from the tag) */

#define DIRECTION_UPLINK 0
#define DIRECTION_DOWNLINK 1

#define RLC_DIRECTION_TAG       0x04
/* 1 byte */

#define RLC_URNTI_TAG           0x05
/* 4 bytes, network order */

#define RLC_RADIO_BEARER_ID_TAG 0x06
/* 1 byte */

#define RLC_LI_SIZE_TAG         0x07
/* 1 byte, enum rlc_li_size value */

/* RLC PDU. Following this tag comes the actual RLC PDU (there is no length, the PDU
   continues until the end of the frame) */
#define RLC_PAYLOAD_TAG         0x01

#endif /* PACKET_RLC_H */
