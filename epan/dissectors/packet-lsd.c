/* packet-lsd.c
 * Local Service Discovery packet dissector
 *
 * From http://bittorrent.org/beps/bep_0014.html
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
#include <wsutil/pint.h>
#include <wsutil/strtoi.h>

void proto_register_lsd(void);
void proto_reg_handoff_lsd(void);

#define LSD_MULTICAST_ADDRESS 0xEFC0988F /* 239.192.152.143 */
#define LSD_PORT 6771

static int proto_lsd = -1;
static int hf_lsd_header = -1;
static int hf_lsd_host = -1;
static int hf_lsd_port = -1;
static int hf_lsd_infohash = -1;
static int hf_lsd_cookie = -1;

static gint ett_lsd = -1;

static expert_field ei_lsd_field = EI_INIT;

static gboolean
parse_string_field(proto_tree *tree, int hf, packet_info *pinfo, tvbuff_t *tvb, int offset, int* next_offset, int* linelen)
{
  guint8 *str;
  header_field_info* hf_info = proto_registrar_get_nth(hf);
  gchar **field_and_value;
  proto_item* ti;
  gchar *p;

  *linelen = tvb_find_line_end(tvb, offset, -1, next_offset, FALSE);
  if (*linelen < 0)
    return FALSE;

  str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, *linelen, ENC_ASCII);
  if (g_ascii_strncasecmp(str, hf_info->name, strlen(hf_info->name)) == 0)
  {
      field_and_value = wmem_strsplit(wmem_packet_scope(), str, ":", 2);
      p = field_and_value[1];
      if (p) {
        while(g_ascii_isspace(*p))
          p++;
        proto_tree_add_string(tree, hf, tvb, offset, *linelen, p);
        return TRUE;
      }
  }
  ti = proto_tree_add_string_format(tree, hf, tvb, offset, *linelen, str, "%s", str);
  expert_add_info_format(pinfo, ti, &ei_lsd_field, "%s field malformed", hf_info->name);

  return TRUE;
}

static int
dissect_lsd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti = NULL;
  proto_tree *lsd_tree;
  int offset = 0, next_offset = 0, linelen;
  guint8 *str;
  gchar **field_and_value;
  guint16 port;
  gboolean valid;

  linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
  if (linelen < 0)
      return 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LSD");
  col_clear(pinfo->cinfo, COL_INFO);

  /* Create display subtree for the protocol */
  ti = proto_tree_add_item(tree, proto_lsd, tvb, 0, -1, ENC_NA);
  lsd_tree = proto_item_add_subtree(ti, ett_lsd);

  proto_tree_add_item(lsd_tree, hf_lsd_header, tvb, offset, linelen, ENC_ASCII|ENC_NA);

  offset = next_offset;
  if (!parse_string_field(lsd_tree, hf_lsd_host, pinfo, tvb, offset, &next_offset, &linelen))
      return offset+linelen;

  offset = next_offset;
  linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
  if (linelen < 0)
      return offset+linelen;
  str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, linelen, ENC_ASCII);
  if (g_ascii_strncasecmp(str, "Port", strlen("Port")) == 0)
  {
    field_and_value = wmem_strsplit(wmem_packet_scope(), str, ":", 2);
    valid = ws_strtou16(field_and_value[1], NULL, &port);
    ti = proto_tree_add_uint(lsd_tree, hf_lsd_port, tvb, offset, linelen, port);
    if (!valid)
    {
      expert_add_info_format(pinfo, ti, &ei_lsd_field, "Port value malformed");
    }
  }
  else
  {
    ti = proto_tree_add_uint(lsd_tree, hf_lsd_port, tvb, offset, 0, 0xFFFF);
    expert_add_info_format(pinfo, ti, &ei_lsd_field, "Port field malformed");
  }
  proto_item_set_len(ti, linelen);

  offset = next_offset;
  if (!parse_string_field(lsd_tree, hf_lsd_infohash, pinfo, tvb, offset, &next_offset, &linelen))
      return offset+linelen;

  offset = next_offset;
  linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
  if (linelen < 0)
      return offset+linelen;
  /* Cookie is optionnal */
  if (tvb_strncaseeql(tvb, offset, "cookie", strlen("cookie")) == 0)
  {
    if (!parse_string_field(lsd_tree, hf_lsd_cookie, pinfo, tvb, offset, &next_offset, &linelen))
      return offset+linelen;
  }

  return tvb_captured_length(tvb);
}

static gboolean
dissect_lsd_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  if (pinfo->dst.type == AT_IPv4 && pntoh32(pinfo->dst.data) == LSD_MULTICAST_ADDRESS && pinfo->destport == LSD_PORT)
      return (dissect_lsd(tvb, pinfo, tree, data) != 0);

  if (pinfo->dst.type == AT_IPv6 && pinfo->destport == LSD_PORT)
      return (dissect_lsd(tvb, pinfo, tree, data) != 0);

  return FALSE;
}

void
proto_register_lsd(void)
{
  static hf_register_info hf[] = {
    { &hf_lsd_header,
      { "Header", "lsd.header",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
    },
    { &hf_lsd_host,
      { "Host", "lsd.host",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
    },
    { &hf_lsd_port,
      { "Port", "lsd.port",
        FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
    },
    { &hf_lsd_infohash,
      { "Infohash", "lsd.infohash",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
    },
    { &hf_lsd_cookie,
      { "cookie", "lsd.cookie",
        FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
    },
  };

  static gint *ett[] = {
    &ett_lsd,
  };

  static ei_register_info ei[] = {
    { &ei_lsd_field, { "lsd.malformed_field", PI_MALFORMED, PI_ERROR, "Malformed LDS field", EXPFILL }},
  };

  expert_module_t* expert_lsd;

  proto_lsd = proto_register_protocol("Local Service Discovery", "LSD", "lsd");

  proto_register_field_array(proto_lsd, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_lsd = expert_register_protocol(proto_lsd);
  expert_register_field_array(expert_lsd, ei, array_length(ei));
}

void
proto_reg_handoff_lsd(void)
{
    heur_dissector_add( "udp", dissect_lsd_heur, "LSD over UDP", "lsd_udp", proto_lsd, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
