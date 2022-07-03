/* packet-ath.c
 * Routines for ATH (Apache Tribes Heartbeat) dissection
 * Copyright 2015, Eugene Adell <eugene.adell@d2-si.eu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/to_str.h>

void proto_register_ath(void);
void proto_reg_handoff_ath(void);

/* IMPORTANT IMPLEMENTATION NOTES
 *
 * You need to be looking at:
 *
 *     http://tomcat.apache.org/tomcat-8.0-doc/cluster-howto.html
 *
 * Tomcat clustering uses two protocols :
 *
 *     - UDP heartbeats to maintain a status of all the members of the cluster
 *
 *     - TCP RMI to send data accross members
 *
 * This dissector is about UDP heartbeats, that we will call ATH, standing for
 *   Apache Tribes Heartbeat. Tribes is the name of the clustering libraries
 *   package of Apache Tomcat.
 *
 */

#define ATH_PORT 45564 /* Not IANA registered */

static int proto_ath = -1;

static int hf_ath_begin   = -1;
static int hf_ath_padding = -1;
static int hf_ath_length  = -1;
static int hf_ath_alive   = -1;
static int hf_ath_port    = -1;
static int hf_ath_sport   = -1;
static int hf_ath_uport   = -1;
static int hf_ath_hlen    = -1;
static int hf_ath_ipv4    = -1;
static int hf_ath_ipv6    = -1;
static int hf_ath_clen    = -1;
static int hf_ath_comm    = -1;
static int hf_ath_dlen    = -1;
static int hf_ath_domain  = -1;
static int hf_ath_unique  = -1;
static int hf_ath_plen    = -1;
static int hf_ath_payload = -1;
static int hf_ath_end     = -1;

static gint ett_ath = -1;

static expert_field ei_ath_hlen_invalid  = EI_INIT;
static expert_field ei_ath_hmark_invalid = EI_INIT;

static gboolean
test_ath(tvbuff_t *tvb)
{
  /* Apache Tribes packets start with "TRIBES-B" in ASCII.
   * tvb_strneql returns -1 if there aren't enough bytes.
   */
  if (tvb_strneql(tvb, 0, "TRIBES-B", 8) != 0) {
    return FALSE;
  }

  return TRUE;
}

static int
dissect_ath(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  int offset = 0;

  /* various lengths as reported in the packet itself */
  guint8 hlen = 0;
  gint32 clen = 0;
  gint32 dlen = 0;
  gint32 plen = 0;

  /* detect the Tribes (Tomcat) version */
  gint   tribes_version_mark;

  /* store the info */
  const gchar *info_srcaddr = "";
  const gchar *info_domain  = "";
  const gchar *info_command = "";

  proto_item *ti, *hlen_item;
  proto_tree *ath_tree;

  if (!test_ath(tvb)) {
    return 0;
  }

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ATH");

  /* Clear out stuff in the info column */
  col_clear(pinfo->cinfo,COL_INFO);

  ti = proto_tree_add_item(tree, proto_ath, tvb, 0, -1, ENC_NA);
  ath_tree = proto_item_add_subtree(ti, ett_ath);

  /* Determine the Tribes version, which means determining the Tomcat version.
   * There are 2 versions : one for Tomcat 6, and one for Tomcat 7/8
   * We know that Tomcat 6 packets end with "-E" (Ox2d 0x45 or 11589 in decimal)
   * and Tomcat 7/8 packets end with "Ox01 0x00" (256 in decimal)
   * This is why we read these 2 last bytes of the packet
   */
  tribes_version_mark = tvb_get_ntohs(tvb, tvb_reported_length(tvb) - 2);

  /* dissecting a Tomcat 6 packet
   */
  if (tribes_version_mark == 11589) { /* "-E" */

    /* BEGIN
     */
      proto_tree_add_item(ath_tree, hf_ath_begin, tvb, offset, 8, ENC_ASCII);
      offset += 8;

      /* LENGTH
       */
      proto_tree_add_item(ath_tree, hf_ath_length, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;

      /* ALIVE TIME
       */
      proto_tree_add_item(ath_tree, hf_ath_alive, tvb, offset, 8, ENC_BIG_ENDIAN);
      offset += 8;

      /* PORT
       */
      proto_tree_add_item(ath_tree, hf_ath_port, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;

      /* SECURE PORT
       */
      proto_tree_add_item(ath_tree, hf_ath_sport, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;

      /* HOST LENGTH
       */
      hlen_item = proto_tree_add_item(ath_tree, hf_ath_hlen, tvb, offset, 1, ENC_BIG_ENDIAN);
      hlen = tvb_get_guint8(tvb, offset);
      offset += 1;

      /* HOST
       */
      if (hlen == 4) {
        proto_tree_add_item(ath_tree, hf_ath_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        info_srcaddr = tvb_ip_to_str(pinfo->pool, tvb, offset);
      } else if (hlen == 6) {
        proto_tree_add_item(ath_tree, hf_ath_ipv6, tvb, offset, 6, ENC_NA);
        info_srcaddr = tvb_ip6_to_str(pinfo->pool, tvb, offset);
      } else {
        expert_add_info(pinfo, hlen_item, &ei_ath_hlen_invalid);
      }
      offset += hlen;

      /* COMMAND LENGTH
       */
      proto_tree_add_item_ret_int(ath_tree, hf_ath_clen, tvb, offset, 4, ENC_BIG_ENDIAN, &clen);
      offset += 4;

      /* COMMAND
       */
      proto_tree_add_item(ath_tree, hf_ath_comm, tvb, offset, clen, ENC_ASCII);
      if (clen != -1)
        info_command = tvb_get_string_enc(pinfo->pool, tvb, offset, clen, ENC_ASCII);
      offset += clen;

      /* DOMAIN LENGTH
       */
      proto_tree_add_item_ret_int(ath_tree, hf_ath_dlen, tvb, offset, 4, ENC_BIG_ENDIAN, &dlen);
      offset += 4;

      /* DOMAIN
       */
      proto_tree_add_item(ath_tree, hf_ath_domain, tvb, offset, dlen, ENC_ASCII);
      if (dlen != 0)
        info_domain = tvb_get_string_enc(pinfo->pool, tvb, offset, dlen, ENC_ASCII);
      offset += dlen;

      /* UNIQUEID
       */
      proto_tree_add_item(ath_tree, hf_ath_unique, tvb, offset, 16, ENC_NA);
      offset += 16;

      /* PAYLOAD LENGTH
       */
      proto_tree_add_item_ret_int(ath_tree, hf_ath_plen, tvb, offset, 4, ENC_BIG_ENDIAN, &plen);
      offset += 4;

      /* PAYLOAD
       */
      proto_tree_add_item(ath_tree, hf_ath_payload, tvb, offset, plen, ENC_ASCII);
      offset += plen;

      /* END
       */
      proto_tree_add_item(ath_tree, hf_ath_end, tvb, offset, 8, ENC_ASCII);
  }

  /* dissecting a Tomcat 7/8 packet
   */
  else if (tribes_version_mark == 256) {

    /* BEGIN
     */
      proto_tree_add_item(ath_tree, hf_ath_begin, tvb, offset, 8, ENC_ASCII);
      offset += 8;

      proto_tree_add_item(ath_tree, hf_ath_padding, tvb, offset, 2, ENC_ASCII|ENC_NA);
      offset += 2;

      /* LENGTH
       */
      proto_tree_add_item(ath_tree, hf_ath_length, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;

      /* ALIVE TIME
       */
      proto_tree_add_item(ath_tree, hf_ath_alive, tvb, offset, 8, ENC_BIG_ENDIAN);
      offset += 8;

      /* PORT
       */
      proto_tree_add_item(ath_tree, hf_ath_port, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;

      /* SECURE PORT
       */
      proto_tree_add_item(ath_tree, hf_ath_sport, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;

      /* UDP PORT, only in Tomcat 7/8
       */
      proto_tree_add_item(ath_tree, hf_ath_uport, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;

      /* HOST LENGTH
       */
      hlen_item = proto_tree_add_item(ath_tree, hf_ath_hlen, tvb, offset, 1, ENC_BIG_ENDIAN);
      hlen = tvb_get_guint8(tvb, offset);
      offset += 1;

      /* HOST
       */
      if (hlen == 4) {
        proto_tree_add_item(ath_tree, hf_ath_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        info_srcaddr = tvb_ip_to_str(pinfo->pool, tvb, offset);
      } else if (hlen == 6) {
        proto_tree_add_item(ath_tree, hf_ath_ipv6, tvb, offset, 6, ENC_NA);
        info_srcaddr = tvb_ip6_to_str(pinfo->pool, tvb, offset);
      } else {
        expert_add_info(pinfo, hlen_item, &ei_ath_hlen_invalid);
      }
      offset += hlen;

      /* COMMAND LENGTH
       */
      proto_tree_add_item_ret_int(ath_tree, hf_ath_clen, tvb, offset, 4, ENC_BIG_ENDIAN, &clen);
      offset += 4;

      /* COMMAND
       */
      proto_tree_add_item(ath_tree, hf_ath_comm, tvb, offset, clen, ENC_ASCII);
      if (clen != -1)
        info_command = tvb_get_string_enc(pinfo->pool, tvb, offset, clen, ENC_ASCII);
      offset += clen;

      /* DOMAIN LENGTH
       */
      proto_tree_add_item_ret_int(ath_tree, hf_ath_dlen, tvb, offset, 4, ENC_BIG_ENDIAN, &dlen);
      offset += 4;

      /* DOMAIN
       */
      proto_tree_add_item(ath_tree, hf_ath_domain, tvb, offset, dlen, ENC_ASCII);
      if (dlen != 0)
        info_domain = tvb_get_string_enc(pinfo->pool, tvb, offset, dlen, ENC_ASCII);
      offset += dlen;

      /* UNIQUEID
       */
      proto_tree_add_item(ath_tree, hf_ath_unique, tvb, offset, 16, ENC_NA);
      offset += 16;

      /* PAYLOAD LENGTH
       */
      proto_tree_add_item_ret_int(ath_tree, hf_ath_plen, tvb, offset, 4, ENC_BIG_ENDIAN, &plen);
      offset += 4;

      /* PAYLOAD
       */
      proto_tree_add_item(ath_tree, hf_ath_payload, tvb, offset, plen, ENC_ASCII);
      offset += plen;

      /* END
       */
      proto_tree_add_item(ath_tree, hf_ath_end, tvb, offset, 8, ENC_ASCII);

  } else {
    proto_tree_add_expert(tree, pinfo, &ei_ath_hmark_invalid, tvb, offset, -1);
    return tvb_captured_length(tvb);
  }

  /* set the INFO column, and we're done !
   */
  if (strcmp(info_command, "") != 0) {
    if (strcmp(info_command, "BABY-ALEX") == 0) {
      if (strcmp(info_domain, "") != 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s is leaving domain %s", info_srcaddr, info_domain);
      } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s is leaving default domain", info_srcaddr);
      }
    } else {
      if (strcmp(info_domain, "") != 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "Heartbeat from %s to domain %s", info_srcaddr, info_domain);
      } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, "Heartbeat from %s to default domain", info_srcaddr);
      }
    }
  } else {
    if (strcmp(info_domain, "") != 0) {
      col_append_fstr(pinfo->cinfo, COL_INFO, "Heartbeat from %s to domain %s", info_srcaddr, info_domain);
    } else {
      col_append_fstr(pinfo->cinfo, COL_INFO, "Heartbeat from %s to default domain", info_srcaddr);
    }
  }

  return tvb_captured_length(tvb);
}

void
proto_register_ath(void)
{

  expert_module_t* expert_ath;

  static hf_register_info hf[] = {
    { &hf_ath_begin,
      { "Begin",  "ath.begin", FT_STRING, BASE_NONE, NULL, 0x0, "Begin mark",
        HFILL }
    },
    { &hf_ath_padding,
      { "Padding",  "ath.padding", FT_UINT16, BASE_HEX, NULL, 0x0, NULL,
        HFILL }
    },
    { &hf_ath_length,
      { "Length",  "ath.length", FT_UINT32, BASE_DEC, NULL, 0x0, "Data Length",
        HFILL }
    },
    { &hf_ath_alive,
      { "Alive Time",  "ath.alive", FT_UINT64, BASE_DEC, NULL, 0x0, "Alive Time counter",
        HFILL }
    },
    { &hf_ath_port,
      { "Port",  "ath.port", FT_UINT32, BASE_DEC, NULL, 0x0, "RMI Port",
        HFILL }
    },
    { &hf_ath_sport,
      { "Secure Port",  "ath.sport", FT_INT32, BASE_DEC, NULL, 0x0, "RMI Secure Port",
        HFILL }
    },
    { &hf_ath_uport,
      { "UDP Port",  "ath.uport", FT_INT32, BASE_DEC, NULL, 0x0, "RMI UDP Port",
        HFILL }
    },
    { &hf_ath_hlen,
      { "Host Length",  "ath.hlen", FT_INT8, BASE_DEC, NULL, 0x0, "Host IP Length",
        HFILL }
    },
    { &hf_ath_ipv4,
      { "Host",  "ath.ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, "IPv4 Host",
        HFILL }
    },
    { &hf_ath_ipv6,
      { "Host",  "ath.ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, "IPv6 Host",
        HFILL }
    },
    { &hf_ath_clen,
      { "Command Length",  "ath.clen", FT_INT32, BASE_DEC, NULL, 0x0, "Command Length for members",
        HFILL }
    },
    { &hf_ath_comm,
      { "Command",  "ath.comm", FT_STRING, BASE_NONE, NULL, 0x0, "Command for members",
        HFILL }
    },
    { &hf_ath_dlen,
      { "Domain Length",  "ath.dlen", FT_INT32, BASE_DEC, NULL, 0x0, "Cluster Domain Length",
        HFILL }
    },
    { &hf_ath_domain,
      { "Domain",  "ath.domain", FT_STRING, BASE_NONE, NULL, 0x0, "Cluster Domain",
        HFILL }
    },
    { &hf_ath_unique,
      { "uniqueId",  "ath.unique", FT_BYTES, BASE_NONE, NULL, 0x0, "UniqueID identifier",
        HFILL }
    },
    { &hf_ath_plen,
      { "Payload Length",  "ath.plen", FT_INT32, BASE_DEC, NULL, 0x0, "Packet Payload Length",
        HFILL }
    },
    { &hf_ath_payload,
      { "Payload",  "ath.payload", FT_STRING, BASE_NONE, NULL, 0x0, "Packet Payload",
        HFILL }
    },
    { &hf_ath_end,
      { "End",  "ath.end", FT_STRING, BASE_NONE, NULL, 0x0, "End mark",
        HFILL }
    },
  };

  static ei_register_info ei[] = {
    { &ei_ath_hlen_invalid, { "ath.hlen.invalid", PI_MALFORMED, PI_ERROR, "Decode aborted: invalid IP length", EXPFILL }},
    { &ei_ath_hmark_invalid, { "ath.hmark.invalid", PI_MALFORMED, PI_ERROR, "Decode aborted: not an ATH packet", EXPFILL }},
  };

  static gint *ett[] = {
    &ett_ath,
  };

  proto_ath = proto_register_protocol("Apache Tribes Heartbeat Protocol", "ATH", "ath");
  proto_register_field_array(proto_ath, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_ath = expert_register_protocol(proto_ath);
  expert_register_field_array(expert_ath, ei, array_length(ei));

}

void
proto_reg_handoff_ath(void)
{
  dissector_handle_t ath_handle;

  ath_handle = create_dissector_handle(dissect_ath, proto_ath);
  dissector_add_uint_with_preference("udp.port", ATH_PORT, ath_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
