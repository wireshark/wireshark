/* packet-homeplug.c
 * Routines for homeplug dissection
 *
 * Copyright 2006, Sebastien Tandel <sebastien[AT]tandel.be>
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>

#include <epan/etypes.h>

#include <epan/proto.h>
#include <epan/ptvcursor.h>



/* METYPE Values */
#define HOMEPLUG_MME_RCE      0x00
#define HOMEPLUG_MME_CER      0x01
#define HOMEPLUG_MME_RPS      0x07
#define HOMEPLUG_MME_PSR      0x08
#define HOMEPLUG_MME_NS	      0x1A

/* Bit mask Operation */
#define HOMEPLUG_MCTRL_RSVD   0x80
#define HOMEPLUG_MCTRL_NE     0x7F

#define HOMEPLUG_MEHDR_MEV    0xE0
#define HOMEPLUG_MEHDR_METYPE 0x1F

#define HOMEPLUG_NS_AC	      0x80
#define HOMEPLUG_NS_ICID      0x7F

#define HOMEPLUG_RCE_CEV      0xF0
#define HOMEPLUG_RCE_RSVD     0x0F

#define HOMEPLUG_CER_CERV     0xF0
#define HOMEPLUG_CER_RSVD     0x0FE0
#define HOMEPLUG_CER_RXTMI    0x1F
#define HOMEPLUG_CER_RATE     0x80
#define HOMEPLUG_CER_BP	      0x40
#define HOMEPLUG_CER_VT11     0x0F
#define HOMEPLUG_CER_RSVD2    0x80
#define HOMEPLUG_CER_NBDAS    0x7F


/*  Length of Network Statistics Response defines whether it is the Basic or
 *  the Extended Response
 */
#define HOMEPLUG_NS_BASIC_LEN 187
#define HOMEPLUG_NS_EXT_LEN   199

/* forward reference */
void proto_reg_handoff_homeplug();

static int proto_homeplug = -1;

static int hf_homeplug_mctrl		= -1;
  static int hf_homeplug_mctrl_reserved = -1;
  static int hf_homeplug_mctrl_ne	= -1;
static int hf_homeplug_mehdr		= -1;
  static int hf_homeplug_mehdr_mev	= -1;
  static int hf_homeplug_mehdr_metype	= -1;
static int hf_homeplug_melen		= -1;
static int hf_homeplug_mme		= -1;
  /* Request Channel Estimation */
  static int hf_homeplug_rce		= -1;
    static int hf_homeplug_rce_cev	= -1;
    static int hf_homeplug_rce_rsvd	= -1;
  /* Channel Estimation Response */
  static int hf_homeplug_cer		= -1;
    static int hf_homeplug_cer_cerv	= -1;
    static int hf_homeplug_cer_rsvd1	= -1;
    static int hf_homeplug_cer_rxtmi	= -1;
    static int hf_homeplug_cer_vt	= -1;
    static int hf_homeplug_cer_rate	= -1;
    static int hf_homeplug_cer_bp	= -1;
    static int hf_homeplug_cer_mod	= -1;
    static int hf_homeplug_cer_vt11	= -1;
    static int hf_homeplug_cer_rsvd2	= -1;
    static int hf_homeplug_cer_nbdas	= -1;
    static int hf_homeplug_cer_bda	= -1;
  /* Request Parameters and Statistics */
  static int hf_homeplug_rps		= -1;
  /* Parameters and Statistics Response */
  static int hf_homeplug_psr		= -1;
    static int hf_homeplug_psr_txack	= -1;
    static int hf_homeplug_psr_txnack	= -1;
    static int hf_homeplug_psr_txfail	= -1;
    static int hf_homeplug_psr_txcloss	= -1;
    static int hf_homeplug_psr_txcoll	= -1;
    static int hf_homeplug_psr_txca3lat	= -1;
    static int hf_homeplug_psr_txca2lat = -1;
    static int hf_homeplug_psr_txca1lat	= -1;
    static int hf_homeplug_psr_txca0lat = -1;
    static int hf_homeplug_psr_rxbp40	= -1;
  /* Network Statistics */
      /* Basic */
  static int hf_homeplug_ns			= -1;
    static int hf_homeplug_ns_netw_ctrl_ac	= -1;
    static int hf_homeplug_ns_netw_ctrl_icid	= -1;
    static int hf_homeplug_ns_netw_ctrl_icid_rsvd= -1;
    static int hf_homeplug_ns_bytes40_robo	= -1;
    static int hf_homeplug_ns_fails_robo	  = -1;
    static int hf_homeplug_ns_drops_robo	= -1;
    static int hf_homeplug_ns_netw_da		= -1;
    static int hf_homeplug_ns_bytes40		= -1;
    static int hf_homeplug_ns_fails		= -1;
    static int hf_homeplug_ns_drops		= -1;
    /* array of 15 elements */
/*    static int hf_homeplug_ns_bytes40_1	= -1;
    static int hf_homeplug_ns_bytes40_1 */
      /* Extended */
    /* array of 6 elements */
/*    static int hf_homeplug_ns_tx_bfr_0_state	= -1;*/

static gint ett_homeplug		= -1;
static gint ett_homeplug_mctrl		= -1;
static gint ett_homeplug_mehdr		= -1;
/* for a later use */
/* static gint ett_homeplug_mme		= -1; */
static gint ett_homeplug_rce		= -1;
static gint ett_homeplug_cer		= -1;
static gint ett_homeplug_rps		= -1;
static gint ett_homeplug_psr		= -1;
static gint ett_homeplug_ns		= -1;
static gint ett_homeplug_tone		= -1;

static guint8 homeplug_ne = 0;
static guint8 homeplug_melen = 0;
static guint8 homeplug_metype = 0;

static guint32	homeplug_offset = 0;

/* IC_ID Values */
#define HOMEPLUG_NS_ICID5130A1		0x00
#define HOMEPLUG_NS_ICID51X1USB		0x01
#define HOMEPLUG_NS_ICID51X1PHY		0x02
#define HOMEPLUG_NS_ICID51X1HOST	0x03
#define HOMEPLUG_NS_ICID5130A2		0x04
#define HOMEPLUG_NS_ICID_RSVD1		0x05
#define HOMEPLUG_NS_ICID_RSVD2		0x06
#define HOMEPLUG_NS_ICID_RSVD3		0x07
/* ICID Bit Mask */
#define HOMEPLUG_NS_ICID_MASK		0x07
#define HOMEPLUG_NS_ICID_RSVD_MASK	0x78
/* string values in function of IC_ID values */
static const value_string homeplug_ns_icid_vals[] = {
    { HOMEPLUG_NS_ICID5130A1,   "INT5130A1" },
    { HOMEPLUG_NS_ICID51X1USB,  "INT51X1 (USB Option)" },
    { HOMEPLUG_NS_ICID51X1PHY,  "INT51X1 (PHY Option)" },
    { HOMEPLUG_NS_ICID51X1HOST, "INT51X1 (Host/DTE Option)" },
    { HOMEPLUG_NS_ICID5130A2,   "INT5130A2" },
    { HOMEPLUG_NS_ICID_RSVD1,   "Reserved"},
    { HOMEPLUG_NS_ICID_RSVD2,   "Reserved"},
    { HOMEPLUG_NS_ICID_RSVD3,   "Reserved"},
    { 0,			NULL }
};

/* Modulation Method Bit Mask */
#define HOMEPLUG_CER_MOD_MASK	        0x30
/* Modulation Method Values */
#define HOMEPLUG_CER_MOD_ROBO		0x00
#define HOMEPLUG_CER_MOD_DBPSK		0x01
#define HOMEPLUG_CER_MOD_DQPSK		0x02
#define	HOMEPLUG_CER_MOD_RSVD		0x03
/* string values in function of Modulation Method Values */
static const value_string homeplug_cer_mod_vals[] = {
  { HOMEPLUG_CER_MOD_ROBO,  "ROBO Modulation"},
  { HOMEPLUG_CER_MOD_DBPSK, "DBPSK Modulation"},
  { HOMEPLUG_CER_MOD_DQPSK, "DQPSK Modulation"},
  { HOMEPLUG_CER_MOD_RSVD,  "Reserved"},
  { 0,			    NULL}
};

#define HOMEPLUG_MCTRL_LEN 1
#define HOMEPLUG_MEHDR_LEN 1
#define HOMEPLUG_MELEN_LEN 1


void
proto_register_homeplug(void)
{
  static hf_register_info hf[] = {
    /* MAC Control Field */
    { &hf_homeplug_mctrl,
      { "MAC Control Field", "homeplug.mctrl",
      FT_UINT8, BASE_DEC, NULL, 0x0, "MAC Control Field", HFILL }
    },

    { &hf_homeplug_mctrl_reserved,
      { "Reserved", "homeplug.mctrl.rsvd",
	FT_NONE, BASE_DEC, NULL, HOMEPLUG_MCTRL_RSVD, "Reserved", HFILL }
    },

    { &hf_homeplug_mctrl_ne,
      { "Number of MAC Data Entries", "homeplug.mctrl.ne",
	FT_UINT8, BASE_DEC, NULL, HOMEPLUG_MCTRL_NE, "Number of MAC Data Entries", HFILL }
    },

    /* MAC Entry Header */
    { &hf_homeplug_mehdr,
      { "MAC Management Entry Header", "homeplug.mehdr",
	FT_NONE, BASE_DEC, NULL, 0x0, "MAC Management Entry Header", HFILL }
    },

    { &hf_homeplug_mehdr_mev,
      { "MAC Entry Version", "homeplug.mehdr.mev",
	FT_UINT8, BASE_DEC, NULL, HOMEPLUG_MEHDR_MEV, "MAC Entry Version", HFILL }
    },

    { &hf_homeplug_mehdr_metype,
      { "MAC Entry Type", "homeplug.mehdr.metype",
	FT_UINT8, BASE_HEX, NULL, HOMEPLUG_MEHDR_METYPE, "MAC Entry Type", HFILL }
    },

    /* MAC Entry Len */
    { &hf_homeplug_melen,
      { "MAC Management Entry Length", "homeplug.melen",
	FT_UINT8, BASE_DEC, NULL, 0x0, "MAC Management Entry Length", HFILL }
    },

    /* MAC Management Entry */
    { &hf_homeplug_mme,
      { "MAC Management Entry Data", "homeplug.mmentry",
	FT_UINT8, BASE_DEC, NULL, 0x0, "MAC Management Entry Data", HFILL }
    },

    /* Request Channel Estimation */
    { &hf_homeplug_rce,
      { "Request Channel Estimation", "homeplug.rce",
	FT_NONE, BASE_DEC, NULL, 0x0, "Request Channel Estimation", HFILL }
    },

    { &hf_homeplug_rce_cev,
      { "Channel Estimation Version", "homeplug.rce.cev",
	FT_UINT8, BASE_DEC, NULL, HOMEPLUG_RCE_CEV, "Channel Estimation Version", HFILL }
    },

    { &hf_homeplug_rce_rsvd,
      { "Reserved", "homeplug.rce.rsvd",
	FT_NONE, BASE_DEC, NULL, HOMEPLUG_RCE_RSVD, "Reserved", HFILL }
    },

    /* Channel Estimation Response */
    { &hf_homeplug_cer,
      { "Channel Estimation Response", "homeplug.cer",
	FT_NONE, BASE_DEC, NULL, 0x0, "Channel Estimation Response", HFILL }
    },

    { &hf_homeplug_cer_cerv,
      { "Channel Estimation Response Version", "homeplug.cer.cerv",
	FT_UINT8, BASE_DEC, NULL, HOMEPLUG_CER_CERV, "Channel Estimation Response Version", HFILL }
    },

    { &hf_homeplug_cer_rsvd1,
      { "Reserved", "homeplug.cer.rsvd1",
	FT_NONE, BASE_DEC, NULL, HOMEPLUG_CER_RSVD, "Reserved", HFILL }
    },

    { &hf_homeplug_cer_rxtmi,
      { "Receive Tone Map Index", "homeplug.cer.rxtmi",
	FT_UINT8, BASE_DEC, NULL, HOMEPLUG_CER_RXTMI, "Receive Tone Map Index", HFILL }
    },

    /* TODO must append vt[79-0] */

    { &hf_homeplug_cer_vt,
      {"Valid Tone Flags", "homeplug.cer.vt",
	FT_UINT8, BASE_HEX, NULL, 0x0, "Valid Tone Flags", HFILL }
    },

    { &hf_homeplug_cer_rate,
      { "FEC Rate", "homeplug.cer.rate",
	FT_UINT8, BASE_DEC, NULL, HOMEPLUG_CER_RATE, "FEC Rate", HFILL }
    },

    { &hf_homeplug_cer_bp,
      { "Bridge Proxy", "homeplug.cer.bp",
	FT_UINT8, BASE_DEC, NULL, HOMEPLUG_CER_BP, "Bridge Proxy", HFILL }
    },

    { &hf_homeplug_cer_mod,
      { "Modulation Method", "homeplug.cer.mod",
	FT_UINT8, BASE_DEC, VALS(&homeplug_cer_mod_vals), HOMEPLUG_CER_MOD_MASK,
	"Modulation Method", HFILL }
    },

    { &hf_homeplug_cer_vt11,
      { "Valid Tone Flags [83-80]", "homeplug.cer.vt11",
	FT_UINT8, BASE_DEC, NULL, HOMEPLUG_CER_VT11, "Valid Tone Flags [83-80]", HFILL }
    },

    { &hf_homeplug_cer_rsvd2,
      { "Reserved", "homeplug.cer.rsvd2",
	FT_UINT8, BASE_DEC, NULL, HOMEPLUG_CER_RSVD2, "Reserved", HFILL }
    },

    { &hf_homeplug_cer_nbdas,
      { "Number Bridged Destination Addresses", "homeplug.cer.nbdas",
	FT_UINT8, BASE_DEC, NULL, HOMEPLUG_CER_NBDAS, "Number Bridged Destination Addresses", HFILL }
    },

    { &hf_homeplug_cer_bda,
      { "Bridged Destination Address", "homeplug.cer.bda",
	FT_ETHER, BASE_HEX, NULL, 0x0, "Bridged Destination Address", HFILL }
    },

    /* Request Parameters and Statistics */
    { &hf_homeplug_rps,
      { "Request Parameters and Statistics", "homeplug.rps",
	FT_NONE, BASE_DEC, NULL, 0x0, "Request Parameters and Statistics", HFILL }
    },

    /* Parameters and Statistics Response */
    { &hf_homeplug_psr,
      { "Parameters and Statistics Response", "homeplug.psr",
	FT_NONE, BASE_DEC, NULL, 0x0, "Parameters and Statistics Response", HFILL }
    },

    { &hf_homeplug_psr_txack,
      { "Transmit ACK Counter", "homeplug.psr.txack",
	FT_UINT16, BASE_DEC, NULL, 0x0, "Transmit ACK Counter", HFILL }
    },

    { &hf_homeplug_psr_txnack,
      { "Transmit NACK Counter", "homeplug.psr.txnack",
	FT_UINT16, BASE_DEC, NULL, 0x0, "Transmit NACK Counter", HFILL }
    },

    { &hf_homeplug_psr_txfail,
      { "Transmit FAIL Counter", "homeplug.psr.txfail",
	FT_UINT16, BASE_DEC, NULL, 0x0, "Transmit FAIL Counter", HFILL }
    },

    { &hf_homeplug_psr_txcloss,
      { "Transmit Contention Loss Counter", "homeplug.psr.txcloss",
	FT_UINT16, BASE_DEC, NULL, 0x0, "Transmit Contention Loss Counter", HFILL }
    },

    { &hf_homeplug_psr_txcoll,
      { "Transmit Collision Counter", "homeplug.psr.txcoll",
	FT_UINT16, BASE_DEC, NULL, 0x0, "Transmit Collision Counter", HFILL }
    },

    { &hf_homeplug_psr_txca3lat,
      { "Transmit CA3 Latency Counter", "homeplug.psr.txca3lat",
	FT_UINT16, BASE_DEC, NULL, 0x0, "Transmit CA3 Latency Counter", HFILL }
    },

    { &hf_homeplug_psr_txca2lat,
      { "Transmit CA2 Latency Counter", "homeplug.psr.txca2lat",
	FT_UINT16, BASE_DEC, NULL, 0x0, "Transmit CA2 Latency Counter", HFILL }
    },
    { &hf_homeplug_psr_txca1lat,
      { "Transmit CA1 Latency Counter", "homeplug.psr.txca1lat",
	FT_UINT16, BASE_DEC, NULL, 0x0, "Transmit CA1 Latency Counter", HFILL }
    },
    { &hf_homeplug_psr_txca0lat,
      { "Transmit CA0 Latency Counter", "homeplug.psr.txca0lat",
	FT_UINT16, BASE_DEC, NULL, 0x0, "Transmit CA0 Latency Counter", HFILL }
    },

    { &hf_homeplug_psr_rxbp40,
      { "Receive Cumulative Bytes per 40-symbol", "homeplug.psr.rxbp40",
	FT_UINT32, BASE_DEC, NULL, 0x0, "Receive Cumulative Bytes per 40-symbol", HFILL }
    },

    /* Network Statistics Basic */
    { &hf_homeplug_ns,
      { "Network Statistics Basic", "homeplug.ns",
	FT_NONE, BASE_DEC, NULL, 0x0, "Network Statistics Basic", HFILL }
    },

    { &hf_homeplug_ns_netw_ctrl_ac,
      { "Action Control", "homeplug.ns.ac",
      FT_BOOLEAN, BASE_DEC, NULL, HOMEPLUG_NS_AC, "Action Control", HFILL }
    },

    { &hf_homeplug_ns_netw_ctrl_icid,
      { "IC_ID", "homeplug.ns.icid",
      FT_UINT8, BASE_HEX, VALS(&homeplug_ns_icid_vals), HOMEPLUG_NS_ICID_MASK, "IC_ID", HFILL }
    },

    { &hf_homeplug_ns_netw_ctrl_icid_rsvd,
      { "IC_ID Reserved", "homeplug.ns.icid",
	FT_NONE, BASE_DEC, NULL, 0x0, "IC_ID Reserved", HFILL }
    },

    { &hf_homeplug_ns_bytes40_robo,
      { "Bytes in 40 symbols in ROBO", "homeplug.ns.bytes40_robo",
	FT_UINT16, BASE_DEC, NULL, 0x0, "Bytes in 40 symbols in ROBO", HFILL }
    },

    { &hf_homeplug_ns_fails_robo,
      { "Fails Received in ROBO", "homeplug.ns.fails_robo",
	FT_UINT16, BASE_DEC, NULL, 0x0, "Fails Received in ROBO", HFILL }
    },

    { &hf_homeplug_ns_drops_robo,
      { "Frame Drops in ROBO", "homeplug.ns.drops_robo",
	FT_UINT16, BASE_DEC, NULL, 0x0, "Frame Drops in ROBO", HFILL }
    },

    /* TODO NETW_DA1 ... */
    { &hf_homeplug_ns_netw_da,
      { "Address of Network DA", "homeplug.ns.netw_da",
	FT_ETHER, BASE_HEX, NULL, 0x0, "Address of Network DA", HFILL }
    },

    { &hf_homeplug_ns_bytes40,
      { "Bytes in 40 symbols", "homeplug.ns.bytes40",
	FT_UINT16, BASE_DEC, NULL, 0x0, "Bytes in 40 symbols", HFILL }
    },

    { &hf_homeplug_ns_fails,
      { "Fails Received", "homeplug.ns.fails",
	FT_UINT16, BASE_DEC, NULL, 0x0, "Fails Received", HFILL }
    },

    { &hf_homeplug_ns_drops,
      { "Frame Drops", "homeplug.ns.drops",
	FT_UINT16, BASE_DEC, NULL, 0x0, "Frame Drops", HFILL }
    }

    /* TODO Network Statistics Extended */
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_homeplug,
    &ett_homeplug_mctrl,
    &ett_homeplug_mehdr,
    &ett_homeplug_rce,
    &ett_homeplug_cer,
    &ett_homeplug_rps,
    &ett_homeplug_psr,
    &ett_homeplug_ns,
    &ett_homeplug_tone,
  };

  proto_homeplug = proto_register_protocol(
					  "HomePlug protocol",  /* Name */
					  "HomePlug",		/* Short Name */
					  "homeplug"		/* Abbrev */
					  );

  proto_register_field_array(proto_homeplug, hf, array_length(hf));

  proto_register_subtree_array(ett, array_length(ett));
}


/* Dissection of MCTRL */
static void dissect_homeplug_mctrl(ptvcursor_t * cursor)
{
  proto_tree *initial_tree = NULL;
  proto_tree *additional_tree = NULL;
  proto_item *it = NULL;

  if (!cursor || !ptvcursor_tree(cursor))
    return;

  initial_tree = ptvcursor_tree(cursor);

  it = ptvcursor_add_no_advance(cursor, hf_homeplug_mctrl, 1, FALSE);
  homeplug_ne = tvb_get_guint8(ptvcursor_tvbuff(cursor),
			       ptvcursor_current_offset(cursor))
		& HOMEPLUG_MCTRL_NE;

  additional_tree = proto_item_add_subtree(it, ett_homeplug_mctrl);
  ptvcursor_set_tree(cursor, additional_tree);
  ptvcursor_add_no_advance(cursor, hf_homeplug_mctrl_reserved, 1, FALSE);
  ptvcursor_add(cursor, hf_homeplug_mctrl_ne, 1, FALSE);

  ptvcursor_set_tree(cursor, initial_tree);
}

/* Dissection of MEHDR */
static void dissect_homeplug_mehdr(ptvcursor_t * cursor)
{
  proto_tree *initial_tree = NULL;
  proto_tree *additional_tree = NULL;
  proto_item *it = NULL;

  if (!cursor || !ptvcursor_tree(cursor))
    return;

  initial_tree = ptvcursor_tree(cursor);

  it = ptvcursor_add_no_advance(cursor, hf_homeplug_mehdr, 0, FALSE);
  homeplug_metype = tvb_get_guint8(ptvcursor_tvbuff(cursor),
				   ptvcursor_current_offset(cursor))
		    & HOMEPLUG_MEHDR_METYPE;

  additional_tree = proto_item_add_subtree(it, ett_homeplug_mehdr);
  ptvcursor_set_tree(cursor, additional_tree);
  ptvcursor_add_no_advance(cursor, hf_homeplug_mehdr_mev, 1, FALSE);
  ptvcursor_add(cursor, hf_homeplug_mehdr_metype, 1, FALSE);

  ptvcursor_set_tree(cursor, initial_tree);
}


/* dissection of MELEN */
static void dissect_homeplug_melen(ptvcursor_t *cursor)
{
  if (!cursor || !ptvcursor_tree(cursor))
    return;

  homeplug_melen = tvb_get_guint8(ptvcursor_tvbuff(cursor),
				  ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_homeplug_melen, 1, FALSE);
}

/* Dissection of Request Channel Estimation MME */
static void dissect_homeplug_rce(ptvcursor_t *cursor)
{
  proto_tree *initial_tree = NULL;
  proto_tree *additional_tree = NULL;
  proto_item *it = NULL;

  if (!cursor || !ptvcursor_tree(cursor))
    return;

  initial_tree = ptvcursor_tree(cursor);

  it = ptvcursor_add_no_advance(cursor, hf_homeplug_rce, homeplug_melen, FALSE);

  additional_tree = proto_item_add_subtree(it , ett_homeplug_rce);
  ptvcursor_set_tree(cursor, additional_tree);
  ptvcursor_add_no_advance(cursor, hf_homeplug_rce_cev, 1, FALSE);
  ptvcursor_add(cursor, hf_homeplug_rce_rsvd, 1, FALSE);

  ptvcursor_set_tree(cursor, initial_tree);
}

/* Dissection of Channel Estimation Response MME */
static void dissect_homeplug_cer(ptvcursor_t *cursor)
{
  proto_tree *initial_tree = NULL;
  proto_tree *additional_tree = NULL;
  proto_item *it = NULL;
  guint8 iTone;
  guint8 BP = 0;
  guint8 iNBDA = 0;

  if (!cursor || !ptvcursor_tree(cursor))
    return;

  initial_tree = ptvcursor_tree(cursor);

  it = ptvcursor_add_no_advance(cursor, hf_homeplug_cer_cerv, homeplug_melen, FALSE);

  additional_tree = proto_item_add_subtree(it, ett_homeplug_cer);
  ptvcursor_set_tree(cursor, additional_tree);
  ptvcursor_add_no_advance(cursor, hf_homeplug_cer_cerv, 1, FALSE);
  ptvcursor_add(cursor, hf_homeplug_cer_rsvd1, 2, FALSE);
  ptvcursor_add(cursor, hf_homeplug_cer_rxtmi, 1, FALSE);

  for (iTone = 0; iTone < 10; iTone++) {
    ptvcursor_add(cursor, hf_homeplug_cer_vt, 1, FALSE);
  }

  ptvcursor_add_no_advance(cursor, hf_homeplug_cer_rate, 1, FALSE);
  ptvcursor_add_no_advance(cursor, hf_homeplug_cer_bp, 1, FALSE);
  BP = tvb_get_guint8(ptvcursor_tvbuff(cursor),
		      ptvcursor_current_offset(cursor)) & HOMEPLUG_CER_BP;
  ptvcursor_add_no_advance(cursor, hf_homeplug_cer_mod, 1, FALSE);
  ptvcursor_add(cursor, hf_homeplug_cer_vt11, 1, FALSE);
  ptvcursor_add_no_advance(cursor, hf_homeplug_cer_rsvd2, 1, FALSE);

  if (BP) {
    iNBDA = tvb_get_guint8(ptvcursor_tvbuff(cursor),
			   ptvcursor_current_offset(cursor))
	    & HOMEPLUG_CER_NBDAS;
    ptvcursor_add(cursor, hf_homeplug_cer_nbdas, 1, FALSE);
    /* TODO : Check on iNBDA! INT51X1 up to 16 dba. But up to 32 for INT51X1 (Host/DTE) */
    for (;iNBDA > 0; iNBDA--) {
      ptvcursor_add(cursor, hf_homeplug_cer_bda, 6, FALSE);
    }
  }

  ptvcursor_set_tree(cursor, initial_tree);
}


/* Dissection of Request Parameters and Statistics MME */
static void dissect_homeplug_rps(ptvcursor_t *cursor)
{
  if (!cursor || !ptvcursor_tree(cursor))
    return;

  ptvcursor_add(cursor, hf_homeplug_rps, 4, FALSE);
}

/* Dissection of Parameters and Statistics Response MME */
static void dissect_homeplug_psr(ptvcursor_t *cursor)
{
  proto_tree *initial_tree = NULL;
  proto_tree *additional_tree = NULL;
  proto_item *it = NULL;

  if (!cursor || !ptvcursor_tree(cursor))
    return;

  initial_tree = ptvcursor_tree(cursor);

  it = ptvcursor_add_no_advance(cursor, hf_homeplug_psr, homeplug_melen, FALSE);

  additional_tree = proto_item_add_subtree(it, ett_homeplug_psr);
  ptvcursor_set_tree(cursor, additional_tree);
  ptvcursor_add(cursor, hf_homeplug_psr_txack, 2, FALSE);
  ptvcursor_add(cursor, hf_homeplug_psr_txnack, 2, FALSE);
  ptvcursor_add(cursor, hf_homeplug_psr_txfail, 2, FALSE);
  ptvcursor_add(cursor, hf_homeplug_psr_txcloss, 2, FALSE);
  ptvcursor_add(cursor, hf_homeplug_psr_txcoll, 2, FALSE);
  ptvcursor_add(cursor, hf_homeplug_psr_txca3lat, 2, FALSE);
  ptvcursor_add(cursor, hf_homeplug_psr_txca2lat, 2, FALSE);
  ptvcursor_add(cursor, hf_homeplug_psr_txca1lat, 2, FALSE);
  ptvcursor_add(cursor, hf_homeplug_psr_txca0lat, 2, FALSE);
  ptvcursor_add(cursor, hf_homeplug_psr_rxbp40, 4, FALSE);

  ptvcursor_set_tree(cursor, initial_tree);
}

/* Dissection of the Network Statistic MME */
static void dissect_homeplug_ns(ptvcursor_t *cursor)
{
  proto_item *it = NULL;
  proto_tree *additional_tree = NULL, *tree_tone = NULL;
  proto_tree *initial_tree = NULL;
  guint8 homeplug_ns_icid_rsvd = 0;
  guint8 iTone = 0;
  guint16 ns_bytes40 = 0;
  guint64 newt_da = 0;
#define NEWT_DA_INEXISTANT G_GINT64_CONSTANT(010000000000U)

  if (!cursor || !ptvcursor_tree(cursor))
    return;

  initial_tree = ptvcursor_tree(cursor);

  /* TODO : test length of the MME : differentiation of NS Basic and Extended */
  it = ptvcursor_add_no_advance(cursor, hf_homeplug_ns, homeplug_melen, FALSE);

  additional_tree = proto_item_add_subtree(it, ett_homeplug_ns);
  ptvcursor_set_tree(cursor, additional_tree);
  ptvcursor_add_no_advance(cursor, hf_homeplug_ns_netw_ctrl_ac, 1, FALSE);
  homeplug_ns_icid_rsvd = tvb_get_guint8(ptvcursor_tvbuff(cursor),
					 ptvcursor_current_offset(cursor))
			  & HOMEPLUG_NS_ICID_RSVD_MASK;

  if (homeplug_ns_icid_rsvd)
    ptvcursor_add(cursor, hf_homeplug_ns_netw_ctrl_icid_rsvd, 1, FALSE);
  else
    ptvcursor_add(cursor, hf_homeplug_ns_netw_ctrl_icid, 1, FALSE);

  ptvcursor_add_no_advance(cursor, hf_homeplug_ns_bytes40_robo, 2, TRUE);
  ns_bytes40 = tvb_get_letohs(ptvcursor_tvbuff(cursor),
			      ptvcursor_current_offset(cursor));
  it = proto_tree_add_text(additional_tree, ptvcursor_tvbuff(cursor),
			   ptvcursor_current_offset(cursor), 2, "MHz :  %.3f",
			   (float)(ns_bytes40)/42);
  ptvcursor_advance(cursor, 2);

  ptvcursor_add(cursor, hf_homeplug_ns_fails_robo, 2, TRUE);
  ptvcursor_add(cursor, hf_homeplug_ns_drops_robo, 2, TRUE);

  while (iTone < 15) {
    newt_da = ((gint64)tvb_get_ntoh24(ptvcursor_tvbuff(cursor),
				      ptvcursor_current_offset(cursor))) << 24;
    newt_da |= tvb_get_ntoh24(ptvcursor_tvbuff(cursor),
			      ptvcursor_current_offset(cursor)+3);

    if (newt_da != NEWT_DA_INEXISTANT) {
      it = proto_tree_add_text(additional_tree, ptvcursor_tvbuff(cursor),
			       ptvcursor_current_offset(cursor), 12,
			       "Tone Map #%d", iTone+1);

      tree_tone = proto_item_add_subtree(it, ett_homeplug_tone);
      ptvcursor_set_tree(cursor, tree_tone);

      ptvcursor_add(cursor, hf_homeplug_ns_netw_da, 6, FALSE);

      ptvcursor_add_no_advance(cursor, hf_homeplug_ns_bytes40, 2, TRUE);
      ns_bytes40 = tvb_get_letohs(ptvcursor_tvbuff(cursor),
				  ptvcursor_current_offset(cursor));
      it = proto_tree_add_text(ptvcursor_tree(cursor), ptvcursor_tvbuff(cursor),
			       ptvcursor_current_offset(cursor), 2,
			       "MHz :  %.3f", (float)(ns_bytes40)/42);
      ptvcursor_advance(cursor, 2);

      ptvcursor_add(cursor, hf_homeplug_ns_fails, 2, TRUE);
      ptvcursor_add(cursor, hf_homeplug_ns_drops, 2, TRUE);
    } else
      it = proto_tree_add_text(additional_tree, ptvcursor_tvbuff(cursor),
			       ptvcursor_current_offset(cursor), 12,
			       "Tone Map #%d does not exist", iTone+1);

      iTone++;
  }

  ptvcursor_set_tree(cursor, initial_tree);
}

static void dissect_homeplug_mme(ptvcursor_t *cursor, packet_info *pinfo)
{
  switch(homeplug_metype) {
    case HOMEPLUG_MME_RCE:
      if (check_col(pinfo->cinfo, COL_INFO)) {
	col_clear(pinfo->cinfo, COL_INFO);
	col_set_str(pinfo->cinfo, COL_INFO, "Request Channel Estimation");
      }
      dissect_homeplug_rce(cursor);
      break;

    case HOMEPLUG_MME_CER:
      if (check_col(pinfo->cinfo, COL_INFO)) {
	col_clear(pinfo->cinfo, COL_INFO);
	col_set_str(pinfo->cinfo, COL_INFO, "Channel Estimation Response");
      }
      dissect_homeplug_cer(cursor);
      break;

    case HOMEPLUG_MME_RPS:
      if (check_col(pinfo->cinfo, COL_INFO)) {
	col_clear(pinfo->cinfo, COL_INFO);
	col_set_str(pinfo->cinfo, COL_INFO, "Request Parameters and Statistics");
      }
      dissect_homeplug_rps(cursor);
      break;

    case HOMEPLUG_MME_PSR:
      if (check_col(pinfo->cinfo, COL_INFO)) {
	col_clear(pinfo->cinfo, COL_INFO);
	col_set_str(pinfo->cinfo, COL_INFO, "Parameters and Statistics Response");
      }
      dissect_homeplug_psr(cursor);
      break;

    case HOMEPLUG_MME_NS:
      if (check_col(pinfo->cinfo, COL_INFO)) {
	col_clear(pinfo->cinfo, COL_INFO);
	col_set_str(pinfo->cinfo, COL_INFO, "Network Statistics");
      }
      dissect_homeplug_ns(cursor);
      break;
  }
}

#define TVB_LEN_GREATEST  1
#define TVB_LEN_UNDEF	  0
#define TVB_LEN_SHORTEST -1
static int check_tvb_length(ptvcursor_t *cursor, const gint length)
{
  if (!cursor)
    return TVB_LEN_UNDEF;

  if (tvb_reported_length_remaining(ptvcursor_tvbuff(cursor),
				    ptvcursor_current_offset(cursor)) < length)
    return TVB_LEN_SHORTEST;

  return TVB_LEN_GREATEST;
}

static void
dissect_homeplug(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *it = NULL;
  proto_tree *homeplug_tree = NULL;
  ptvcursor_t *cursor = NULL;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HomePlug");

  /* Clear out stuff in the info column */
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_clear(pinfo->cinfo, COL_INFO);
    col_set_str(pinfo->cinfo, COL_INFO, "MAC Management");
  }

  homeplug_offset = 0;

  if (tree) {
    it = proto_tree_add_item(tree, proto_homeplug, tvb, homeplug_offset, -1, FALSE);
    homeplug_tree = proto_item_add_subtree(it, ett_homeplug);
    cursor = ptvcursor_new(homeplug_tree, tvb, 0);
  }

  /*  We do not have enough data to read mctrl field stop the dissection */
  if (check_tvb_length(cursor, HOMEPLUG_MCTRL_LEN) != TVB_LEN_SHORTEST) {

    dissect_homeplug_mctrl(cursor);

    /*  homeplug_ne indicates the number of MME entries. This field is fetched
     *  from MCTRL.
     */
    for (; homeplug_ne > 0; homeplug_ne--) {

      /* Check we have enough data in tvb to read MEHDR */
      if (check_tvb_length(cursor, HOMEPLUG_MEHDR_LEN) == TVB_LEN_SHORTEST)
	break;
      dissect_homeplug_mehdr(cursor);

      /* Check we have enough data in tvb to read MELEN */
      if (check_tvb_length(cursor, HOMEPLUG_MELEN_LEN) == TVB_LEN_SHORTEST)
	break;
      dissect_homeplug_melen(cursor);

      dissect_homeplug_mme(cursor, pinfo);
    }
  }

  if (cursor)
    ptvcursor_free(cursor);
}

static dissector_handle_t homeplug_handle;

void
proto_reg_handoff_homeplug(void)
{
  static gboolean initialised = FALSE;

  if (!initialised) {
    homeplug_handle = create_dissector_handle(dissect_homeplug, proto_homeplug);
    dissector_add("ethertype", ETHERTYPE_HOMEPLUG, homeplug_handle);
    initialised = TRUE;
  }
}
