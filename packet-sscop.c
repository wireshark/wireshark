/* packet-sscop.c
 * Routines for SSCOP (Q.2110, Q.SAAL) frame disassembly
 * Guy Harris <guy@alum.mit.edu>
 *
 * $Id: packet-sscop.c,v 1.2 1999/11/19 09:10:22 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <stdio.h>
#include <glib.h>
#include <string.h>
#include "packet.h"

static int proto_sscop = -1;

static gint ett_sscop = -1;

/*
 * See
 *
 *	http://www.protocols.com/pbook/atmsig.htm
 *
 * for some information on SSCOP, although, alas, not the actual PDU
 * type values - those I got from the FreeBSD 3.2 ATM code.
 */

/*
 * SSCOP PDU types.
 */
#define	SSCOP_TYPE_MASK	0x0f

#define	SSCOP_BGN	0x01	/* Begin */
#define	SSCOP_BGAK	0x02	/* Begin Acknowledge */
#define	SSCOP_BGREJ	0x07	/* Begin Reject */
#define	SSCOP_END	0x03	/* End */
#define	SSCOP_ENDAK	0x04	/* End Acknowledge */
#define	SSCOP_RS	0x05	/* Resynchronization */
#define	SSCOP_RSAK	0x06	/* Resynchronization Acknowledge */
#define	SSCOP_SD	0x08	/* Sequenced Data */
#define	SSCOP_SDP	0x09	/* Sequenced Data with Poll */
#define	SSCOP_POLL	0x0a	/* Status Request */
#define	SSCOP_STAT	0x0b	/* Solicited Status Response */
#define	SSCOP_USTAT	0x0c	/* Unsolicited Status Response */
#define	SSCOP_UD	0x0d	/* Unnumbered Data */
#define	SSCOP_MD	0x0e	/* Management Data */
#define	SSCOP_ER	0x09	/* Error Recovery */
#define	SSCOP_ERAK	0x0f	/* Error Acknowledge */

/*
 * XXX - how to distinguish SDP from ER?
 */
static const value_string sscop_type_vals[] = {
	{ SSCOP_BGN,   "Begin" },
	{ SSCOP_BGAK,  "Begin Acknowledge" },
	{ SSCOP_BGREJ, "Begin Reject" },
	{ SSCOP_END,   "End" },
	{ SSCOP_ENDAK, "End Acknowledge" },
	{ SSCOP_RS,    "Resynchronization" },
	{ SSCOP_RSAK,  "Resynchronization Acknowledge" },
	{ SSCOP_SD,    "Sequenced Data" },
#if 0
	{ SSCOP_SDP,   "Sequenced Data with Poll" },
#endif
	{ SSCOP_POLL,  "Status Request" },
	{ SSCOP_STAT,  "Solicited Status Response" },
	{ SSCOP_USTAT, "Unsolicited Status Response" },
	{ SSCOP_UD,    "Unnumbered Data" },
	{ SSCOP_MD,    "Management Data" },
	{ SSCOP_ER,    "Error Recovery" },
	{ SSCOP_ERAK,  "Error Acknowledge" },
	{ 0,            NULL }
};

/*
 * The SSCOP "header" is a trailer, so the "offsets" are computed based
 * on the length of the packet.
 */

/*
 * PDU type.
 */
#define	SSCOP_PDU_TYPE	(pi.len - 4)	/* single byte */

/*
 * Begin PDU, Begin Acknowledge PDU (no N(SQ) in it), Resynchronization
 * PDU, Resynchronization Acknowledge PDU (no N(SQ) in it in Q.SAAL),
 * Error Recovery PDU, Error Recovery Acknoledge PDU (no N(SQ) in it).
 */
#define	SSCOP_N_SQ	(pi.len - 8)	/* lower 3 bytes thereof */
#define	SSCOP_N_MR	(pi.len - 4)	/* lower 3 bytes thereof */

/*
 * Sequenced Data PDU (no N(PS) in it), Sequenced Data with Poll PDU,
 * Poll PDU.
 */
#define	SSCOP_N_PS	(pi.len - 8)	/* lower 3 bytes thereof */
#define	SSCOP_N_S	(pi.len - 4)	/* lower 3 bytes thereof */

/*
 * Solicited Status PDU, Unsolicited Status PDU (no N(PS) in it).
 */
#define	SSCOP_SS_N_PS	(pi.len - 12)	/* lower 3 bytes thereof */
#define	SSCOP_SS_N_MR	(pi.len - 8)	/* lower 3 bytes thereof */
#define	SSCOP_SS_N_R	(pi.len - 4)	/* lower 3 bytes thereof */

void
dissect_sscop(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) 
{
  proto_item *ti;
  proto_tree *sscop_tree = NULL;
  guint8 pdu_type;
  int pdu_len;
  int pad_len;

  /*
   * The SSCOP "header" is a trailer, and the PDU type is in the
   * last-minus-3 byte of the frame; if the captured length is less
   * than the actual length by 3 or more bytes, give up, as we don't
   * have the PDU type.
   */
  if ((pi.len - pi.captured_len) >= 3) {
    dissect_data(pd, offset, fd, tree);
    return;
  }
  pdu_type = pd[SSCOP_PDU_TYPE] & SSCOP_TYPE_MASK;
  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "SSCOP");
  if (check_col(fd, COL_INFO))
    col_add_str(fd, COL_INFO, val_to_str(pdu_type, sscop_type_vals,
					"Unknown PDU type (0x%02x)"));

  /*
   * Find the length of the PDU and, if there's any payload and
   * padding, the length of the padding.
   */
  switch (pdu_type) {

  case SSCOP_SD:
    pad_len = (pd[SSCOP_PDU_TYPE] >> 6) & 0x03;
    pdu_len = 4;
    break;

#if 0
  case SSCOP_SDP:
    pad_len = (pd[SSCOP_PDU_TYPE] >> 6) & 0x03;
    pdu_len = 8;
    break;
#endif

  case SSCOP_UD:
    pad_len = (pd[SSCOP_PDU_TYPE] >> 6) & 0x03;
    pdu_len = 4;
    break;

  default:
    pad_len = 0;
    pdu_len = pi.len;	/* No payload, just SSCOP */
    break;
  }
  if (tree) {
    ti = proto_tree_add_item_format(tree, proto_sscop, pi.len - pdu_len,
    					pdu_len, NULL, "SSCOP");
    sscop_tree = proto_item_add_subtree(ti, ett_sscop);
    switch (pdu_type) {

    case SSCOP_BGN:
    case SSCOP_BGAK:
    case SSCOP_RS:
    case SSCOP_ER:
      proto_tree_add_text(sscop_tree, SSCOP_N_SQ + 1, 3,
          "N(SQ): %u", pntohl(&pd[SSCOP_N_SQ]) & 0xFFFFFF);
      proto_tree_add_text(sscop_tree, SSCOP_N_MR + 1, 3,
          "N(MR): %u", pntohl(&pd[SSCOP_N_MR]) & 0xFFFFFF);
      break;

    case SSCOP_RSAK:
      proto_tree_add_text(sscop_tree, SSCOP_N_MR + 1, 3,
          "N(MR): %u", pntohl(&pd[SSCOP_N_MR]) & 0xFFFFFF);
      break;

    case SSCOP_ERAK:
      proto_tree_add_text(sscop_tree, SSCOP_N_MR + 3, 3,
          "N(MR): %u", pntohl(&pd[SSCOP_N_MR]) & 0xFFFFFF);
      break;

    case SSCOP_SD:
      proto_tree_add_text(sscop_tree, SSCOP_N_S + 1, 3,
          "N(S): %u", pntohl(&pd[SSCOP_N_S]) & 0xFFFFFF);
      break;

#if 0
    case SSCOP_SDP:
#endif
    case SSCOP_POLL:
      proto_tree_add_text(sscop_tree, SSCOP_N_PS + 1, 3,
          "N(PS): %u", pntohl(&pd[SSCOP_N_PS]) & 0xFFFFFF);
      proto_tree_add_text(sscop_tree, SSCOP_N_S + 1, 3,
          "N(S): %u", pntohl(&pd[SSCOP_N_S]) & 0xFFFFFF);
      break;

    case SSCOP_STAT:
      /*
       * XXX - dissect the list elements....
       */
      proto_tree_add_text(sscop_tree, SSCOP_SS_N_PS + 1, 3,
          "N(PS): %u", pntohl(&pd[SSCOP_SS_N_PS]) & 0xFFFFFF);
      proto_tree_add_text(sscop_tree, SSCOP_SS_N_MR + 1, 3,
          "N(MR): %u", pntohl(&pd[SSCOP_SS_N_MR]) & 0xFFFFFF);
      proto_tree_add_text(sscop_tree, SSCOP_SS_N_R + 1, 3,
          "N(R): %u", pntohl(&pd[SSCOP_SS_N_R]) & 0xFFFFFF);
      break;

    case SSCOP_USTAT:
      /*
       * XXX - dissect the list elements....
       */
      proto_tree_add_text(sscop_tree, SSCOP_SS_N_MR + 1, 3,
          "N(MR): %u", pntohl(&pd[SSCOP_SS_N_MR]) & 0xFFFFFF);
      proto_tree_add_text(sscop_tree, SSCOP_SS_N_R + 1, 3,
          "N(R): %u", pntohl(&pd[SSCOP_SS_N_R]) & 0xFFFFFF);
      break;
    }

    proto_tree_add_text(sscop_tree, SSCOP_PDU_TYPE, 1,
			"PDU Type: %s",
			val_to_str(pdu_type, sscop_type_vals,
				"Unknown (0x%02x)"));
  }

  /*
   * Dissect the payload, if any.
   *
   * XXX - what about a Management Data PDU?
   */
  switch (pdu_type) {

  case SSCOP_SD:
  case SSCOP_UD:
    if (tree) {
      proto_tree_add_text(sscop_tree, SSCOP_PDU_TYPE, 1,
			"Pad length: %u", pad_len);
    }

    /*
     * Compute length of data in PDU - subtract the trailer length
     * and the pad length.
     */
    pi.len -= (pdu_len + pad_len);
    if (pi.len < pi.captured_len)
      pi.captured_len = pi.len;
    dissect_data(pd, offset, fd, tree);
    break;
  }
}

void
proto_register_sscop(void)
{
	static gint *ett[] = {
		&ett_sscop,
	};
	proto_sscop = proto_register_protocol("SSCOP", "sscop");
	proto_register_subtree_array(ett, array_length(ett));
}
