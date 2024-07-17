/* packet-netanalyzer.c
 * Dissector for Hilscher netANALYZER frames.
 * Copyright 2008-2016, Hilscher GmbH, Holger Pfrommer hpfrommer[AT]hilscher.com
 *
 * Packet structure:
 * +---------------------------+
 * |           Header          |
 * |         (4 Octets)        |
 * +---------------------------+
 * |           Payload         |
 * .                           .
 * .                           .
 * .                           .
 *
 * Description:
 * The header field contains a 32-bit value in little-endian byte order.
 * The low-order 8 bits are a set of error flags for the packet:
 *     0x00000001 - MII RX_ER
 *     0x00000002 - alignment error
 *     0x00000004 - FCS error
 *     0x00000008 - frame too long
 *     0x00000010 - SFD error
 *     0x00000020 - frame shorter than 64 bytes
 *     0x00000040 - preamble shorter than 7 bytes
 *     0x00000080 - preamble longer than 7 bytes/li>
 * The next bit, 0x00000100, is set if the packet arrived on the GPIO port rather tha the Ethernet port.
 * The next bit, 0x00000200, is set if the packet was received in transparent capture mode.
 *   That should never be set for LINKTYPE_NETANALYZER and should always be set for LINKTYPE_NETANALYZER_TRANSPARENT.
 * The next 4 bits, 0x00003C00, are a bitfield giving the version of the header field; version can be 1 or 2.
 * The next 2 bits, 0x0000C000, are the capture port/GPIO number, from 0 to 3.
 * The next 12 bits, 0x0FFF0000, are the frame length, in bytes.
 * The topmost 4 bits, 0xF0000000, for version 2 header, these bits are the type of the following packet
 *                                   (0: Ethernet, 1: PROFIBUS, 2: buffer state entry, 3: timetick, 4..15: reserved).
 * The payload is an Ethernet frame, beginning with the MAC header and ending with the FCS, for LINKTYPE_NETANALYZER,
 *   and an Ethernet frame, beginning with the preamble and ending with the FCS, for LINKTYPE_NETANALYZER_TRANSPARENT.
 *
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald[AT]wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <wiretap/wtap.h>

void proto_register_netanalyzer(void);
void proto_reg_handoff_netanalyzer(void);

static dissector_handle_t netana_handle;
static dissector_handle_t netana_handle_transparent;

#define HEADER_SIZE  4
#define INFO_TYPE_OFFSET    18

#define MSK_RX_ERR             0x01
#define MSK_ALIGN_ERR          0x02
#define MSK_FCS_ERROR          0x04
#define MSK_TOO_LONG           0x08
#define MSK_SFD_ERROR          0x10
#define MSK_SHORT_FRAME        0x20
#define MSK_SHORT_PREAMBLE     0x40
#define MSK_LONG_PREAMBLE      0x80

static const char *msk_strings[] = {
  "MII RX_ER error",                /* 0x01 */
  "Alignment error",                /* 0x02 */
  "FCS error",                      /* 0x04 */
  "Frame too long",                 /* 0x08 */
  "No valid SFD found",             /* 0x10 */
  "Frame smaller 64 bytes",         /* 0x20 */
  "Preamble shorter than 7 bytes",  /* 0x40 */
  "Preamble longer than 7 bytes"    /* 0x80 */
};

#define SRT_TYPE              28
#define SRT_PORT_NUM           6
#define SRT_VERSION            2
#define SRT_GPIO_FLAG          0
#define MSK_PACKET_STATUS      0xff
#define MSK_LENGTH             0x0fff
#define MSK_TRANSPARENT_MODE   0x02

#define MSK_BUF_STATE         0x1
#define SRT_BUF_ID            4
#define MSK_BUF_ID            0xf0

#define VAL_TYPE_ETH            0
#define VAL_TYPE_PB             1
#define VAL_TYPE_BUF            2
#define VAL_TYPE_TICK           3


static const value_string gpio_number[] = {
  { 0x0, "GPIO 0" },
  { 0x1, "GPIO 1" },
  { 0x2, "GPIO 2" },
  { 0x3, "GPIO 3" },
  { 0,   NULL }
};

static const value_string gpio_edge_vals[] = {
  { 0x0, "Rising edge" },
  { 0x1, "Falling edge" },
  { 0,   NULL }
};

static const value_string buf_state_vals[] = {
  { 0x0, "Buffer overflow, frames will be dropped until next buffer recovery" },
  { 0x1, "Buffer recovery, frame reception has recovered" },
  { 0,   NULL }
};

static const value_string buf_source_vals[] = {
  { 0x0, "Backend RX FIFO" },
  { 0x1, "netX URX FIFO" },
  { 0x2, "netX INTRAM buffer" },
  { 0x3, "Host buffer" },
  { 0x4, "Capture driver (WinPcap)" },
  { 0,   NULL }
};


static dissector_handle_t  eth_dissector_handle;

static int   proto_netanalyzer;

static int   hf_netanalyzer_gpio;
static int   hf_netanalyzer_gpio_number;
static int   hf_netanalyzer_gpio_edge;
static int   hf_netanalyzer_eth;
static int   hf_netanalyzer_port;
static int   hf_netanalyzer_length;
static int   hf_netanalyzer_status;
static int   hf_netanalyzer_status_rx_err;
static int   hf_netanalyzer_status_align_err;
static int   hf_netanalyzer_status_fcs;
static int   hf_netanalyzer_status_too_long;
static int   hf_netanalyzer_status_sfd_error;
static int   hf_netanalyzer_status_short_frame;
static int   hf_netanalyzer_status_short_preamble;
static int   hf_netanalyzer_status_long_preamble;
static int   hf_netanalyzer_buf;
static int   hf_netanalyzer_buf_state;
static int   hf_netanalyzer_buf_source;
static int   hf_netanalyzer_timetick;

static int * const hfx_netanalyzer_status[] = {
  &hf_netanalyzer_status_rx_err,
  &hf_netanalyzer_status_align_err,
  &hf_netanalyzer_status_fcs,
  &hf_netanalyzer_status_too_long,
  &hf_netanalyzer_status_sfd_error,
  &hf_netanalyzer_status_short_frame,
  &hf_netanalyzer_status_short_preamble,
  &hf_netanalyzer_status_long_preamble,
  NULL
};

static int   ett_netanalyzer;
static int   ett_netanalyzer_gpio;
static int   ett_netanalyzer_status;
static int   ett_netanalyzer_transparent;
static int   ett_netanalyzer_buf;

static expert_field ei_netanalyzer_header_wrong;
static expert_field ei_netanalyzer_gpio_def_none;
static expert_field ei_netanalyzer_header_none;
static expert_field ei_netanalyzer_transparent_frame;
static expert_field ei_netanalyzer_alignment_error;
static expert_field ei_netanalyzer_not_implemented;

/* common routine for Ethernet and transparent mode */
static int
dissect_netanalyzer_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item              *ti = NULL;
  proto_tree              *netanalyzer_header_tree = NULL;
  uint32_t                packet_status;
  uint32_t                port_num;
  uint32_t                frame_length;
  unsigned                is_gpio;
  uint32_t                offset;
  unsigned                gpio_num;
  unsigned                gpio_edge;
  unsigned                version;
  unsigned                type;
  unsigned                idx;
  unsigned                buf_state;
  unsigned                buf_source;

  if (tree)
  {
    /* generate netANALYZER tree */
    ti = proto_tree_add_item(tree, proto_netanalyzer, tvb, 0, HEADER_SIZE, ENC_NA);
    netanalyzer_header_tree = proto_item_add_subtree(ti, ett_netanalyzer);

    is_gpio = (tvb_get_uint8(tvb, 1) >> SRT_GPIO_FLAG) & 0x1;

    if (!is_gpio)
    {
      /* normal packet, no GPIO */

      /* decode version */
      version = (tvb_get_uint8(tvb, 1) >> SRT_VERSION) & 0xf;
      type    = (tvb_get_uint32(tvb, 0, ENC_LITTLE_ENDIAN) >> SRT_TYPE) & 0xf;

      if ((version == 1) || ((version == 2) && (type == VAL_TYPE_ETH)))
      {
        proto_tree_add_none_format(netanalyzer_header_tree, hf_netanalyzer_eth, tvb, 0, 0, "Ethernet frame");

        /* decode port */
        port_num = (tvb_get_uint8(tvb, 1) >> SRT_PORT_NUM) & 0x3;
        proto_tree_add_uint(netanalyzer_header_tree, hf_netanalyzer_port, tvb, 0, 4, port_num);
        proto_item_append_text(ti, " (Port: %u, ", port_num);

        /* decode length */
        frame_length = tvb_get_letohs(tvb, 2) & MSK_LENGTH;
        proto_tree_add_uint(netanalyzer_header_tree, hf_netanalyzer_length, tvb, 0, 4, frame_length);
        proto_item_append_text(ti, "Length: %u byte%s, ", frame_length, (frame_length == 1) ? "" : "s");

        /* decode status */
        proto_item_append_text(ti, "Status: ");
        packet_status = tvb_get_uint8(tvb, 0);
        if (packet_status == 0)
        {
          proto_tree_add_uint_format_value(netanalyzer_header_tree, hf_netanalyzer_status, tvb, 0, 1,
            packet_status, "No Error");
          proto_item_append_text(ti, "No Error)");
        }
        else
        {
          wmem_strbuf_t      *strbuf;
          bool                first = true;

          proto_tree_add_bitmask(netanalyzer_header_tree, tvb, 0, hf_netanalyzer_status, ett_netanalyzer_status, hfx_netanalyzer_status, ENC_LITTLE_ENDIAN);

          strbuf = wmem_strbuf_create(pinfo->pool);
          for (idx = 0; idx < 8; idx++)
          {
            if (packet_status & (1 << idx))
            {
              if (first)
              {
                first = false;
              }
              else
              {
                wmem_strbuf_append(strbuf, ", ");
              }
              wmem_strbuf_append(strbuf, msk_strings[idx]);
            }
          }
          proto_item_append_text(ti, "%s)", wmem_strbuf_get_str(strbuf));
        }

        /* decode transparent mode */
        if (tvb_get_uint8(tvb, 1) & MSK_TRANSPARENT_MODE)
        {
          proto_tree_add_expert(netanalyzer_header_tree, pinfo, &ei_netanalyzer_transparent_frame, tvb, 0, 4);
          proto_item_append_text(ti, ", Transparent Mode");

          if (packet_status & MSK_ALIGN_ERR)
          {
            proto_tree_add_expert(netanalyzer_header_tree, pinfo, &ei_netanalyzer_alignment_error, tvb, tvb_captured_length(tvb) - 1, 1);
          }
        }
      }
      else if ((version == 2) && (type == VAL_TYPE_PB))
      {
        /* currently not implemented */
        expert_add_info(pinfo, ti, &ei_netanalyzer_not_implemented);
        return false;
      }
      else if ((version == 2) && (type == VAL_TYPE_BUF))
      {
        proto_tree_add_none_format(netanalyzer_header_tree, hf_netanalyzer_buf, tvb, 0, 0, "Buffer state entry");
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "netANALYZER");

        buf_state = tvb_get_uint8(tvb, 0) & MSK_BUF_STATE;
        if (buf_state == 0)
        {
          col_set_str(pinfo->cinfo, COL_INFO, "Buffer overflow");
        }
        else
        {
          col_set_str(pinfo->cinfo, COL_INFO, "Buffer recovery");
        }
        proto_item_append_text(ti, " (%s)", buf_state_vals[buf_state].strptr);

        /* decode buffer state */
        proto_tree_add_uint(ti, hf_netanalyzer_buf_state, tvb, 0, 1, buf_state);
        port_num = (tvb_get_uint8(tvb, 1) >> SRT_PORT_NUM) & 0x3;
        proto_tree_add_uint(ti, hf_netanalyzer_port, tvb, 0, 4, port_num);
        buf_source = (tvb_get_uint8(tvb, 0) & MSK_BUF_ID) >> SRT_BUF_ID;
        proto_tree_add_uint(ti, hf_netanalyzer_buf_source, tvb, 0, 1, buf_source);

        return false;
      }
      else if ((version == 2) && (type == VAL_TYPE_TICK))
      {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "netANALYZER");
        col_set_str(pinfo->cinfo, COL_INFO, "Time tick");
        proto_item_append_text(ti, " (Time tick)");
        proto_tree_add_none_format(netanalyzer_header_tree, hf_netanalyzer_timetick, tvb, 0, 0, "Time tick");
        return false;
      }
      else
      {
        /* something is wrong */
        expert_add_info(pinfo, ti, &ei_netanalyzer_header_wrong);
        return false;
      }
    }
    else
    {
      unsigned char *szTemp;

      /* check consistency */
      if ( (tvb_get_uint8(tvb, 10) == 0x00) &&
           (tvb_get_uint8(tvb, 11) == 0x02) &&
           (tvb_get_uint8(tvb, 12) == 0xa2) &&
           (tvb_get_uint8(tvb, 13) == 0xff) &&
           (tvb_get_uint8(tvb, 14) == 0xff) &&
           (tvb_get_uint8(tvb, 15) == 0xff) &&
           (tvb_get_uint8(tvb, 16) == 0x88) &&
           (tvb_get_uint8(tvb, 17) == 0xff) &&
           (tvb_get_uint8(tvb, INFO_TYPE_OFFSET) == 0x00) )
      {
#define MAX_BUFFER 255
        szTemp=(unsigned char *)wmem_alloc(wmem_epan_scope(), MAX_BUFFER);

        /* everything ok */
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "netANALYZER");
        offset = INFO_TYPE_OFFSET;
        proto_tree_add_none_format(netanalyzer_header_tree, hf_netanalyzer_gpio, tvb, 0, 0, "GPIO event");
        proto_item_append_text(ti, " (GPIO event)");

        /* GPIO number */
        offset++;
        proto_tree_add_item (netanalyzer_header_tree, hf_netanalyzer_gpio_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        gpio_num = (tvb_get_uint8(tvb, offset) & 0x03);

        /* GPIO edge */
        offset++;
        ti = proto_tree_add_item (netanalyzer_header_tree, hf_netanalyzer_gpio_edge, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        gpio_edge = (tvb_get_uint8(tvb, offset) & 0x01);

        snprintf(szTemp, MAX_BUFFER,
                   "GPIO event on GPIO %d (%sing edge)", gpio_num, (gpio_edge == 0x00) ? "ris" : "fall");

        col_add_str(pinfo->cinfo, COL_INFO, szTemp);
        proto_item_append_text(ti, " %s", szTemp);
      }
      else
      {
        /* something is wrong */
        expert_add_info(pinfo, ti, &ei_netanalyzer_gpio_def_none);
      }
      return false;
    }
  }
  return true;
}


/* Ethernet capture mode */
static int
dissect_netanalyzer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  tvbuff_t                *next_tvb;

  if (tvb_reported_length(tvb) >= 4)
  {
    /* generate tvb subset for Ethernet frame */
    if (dissect_netanalyzer_common(tvb, pinfo, tree))
    {
      /* hand off to eth dissector with the new tvb subset */
      next_tvb = tvb_new_subset_remaining(tvb, 4);
      call_dissector(eth_dissector_handle, next_tvb, pinfo, tree);
    }
  }
  else
  {
    /* something is wrong */
    proto_tree_add_expert_format(tree, pinfo, &ei_netanalyzer_header_none, tvb, 4, -1,
        "netANALYZER - No netANALYZER header found");
  }
  return tvb_captured_length(tvb);
}


/* Transparent capture mode */
static int
dissect_netanalyzer_transparent(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree              *transparent_payload_tree = NULL;
  tvbuff_t                *next_tvb;

  if (tvb_reported_length(tvb) >= 4)
  {
    /* generate tvb subset for Ethernet frame */
    if (dissect_netanalyzer_common(tvb, pinfo, tree))
    {
      /* do not hand off transparent packet for further Ethernet dissectors
       * as normally the transparent mode is used for low level analysis
       * where dissecting the frame's content wouldn't make much sense
       * use data dissector instead */
      transparent_payload_tree = proto_tree_add_subtree(tree, tvb, 4, tvb_captured_length(tvb)-4,
                                    ett_netanalyzer_transparent, NULL, "Raw packet data");
      next_tvb = tvb_new_subset_remaining(tvb, 4);
      call_data_dissector(next_tvb, pinfo, transparent_payload_tree);

      col_set_str(pinfo->cinfo, COL_PROTOCOL, "netANALYZER");
      col_set_str(pinfo->cinfo, COL_INFO, "Frame captured in transparent mode");
    }
  }
  else
  {
    /* something is wrong */
    proto_tree_add_expert_format(tree, pinfo, &ei_netanalyzer_header_none, tvb, 4, -1,
        "netANALYZER transparent mode - No netANALYZER header found");
  }
  return tvb_captured_length(tvb);
}


void proto_register_netanalyzer(void)
{
  static hf_register_info hf[] = {
    { &hf_netanalyzer_gpio,
      { "GPIO event", "netanalyzer.gpio_event",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "Shows the occurrence of an digital switching event", HFILL }
    },
    { &hf_netanalyzer_gpio_number,
      { "GPIO event on", "netanalyzer.gpio_event.gpio_number",
        FT_UINT8, BASE_HEX, VALS(gpio_number), 0x0,
        "GPIO event on GPIO number", HFILL }
    },
    { &hf_netanalyzer_gpio_edge,
      { "GPIO event type", "netanalyzer.gpio_event.gpio_edge",
        FT_UINT8, BASE_HEX, VALS(gpio_edge_vals), 0x0,
        "GPIO edge of GPIO event", HFILL }
    },
    { &hf_netanalyzer_eth,
      { "Ethernet frame", "netanalyzer.eth",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "This is an Ethernet frame", HFILL }
    },
    { &hf_netanalyzer_port,
      { "Reception Port", "netanalyzer.port",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "netANALYZER reception port", HFILL }
    },
    { &hf_netanalyzer_length,
      { "Ethernet frame length", "netanalyzer.framelen",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Actual Ethernet frame length", HFILL }
    },
    { &hf_netanalyzer_status,
      { "Status", "netanalyzer.packetstatus",
        FT_UINT8, BASE_HEX, NULL, MSK_PACKET_STATUS,
        "Status of Ethernet frame", HFILL }
    },
    { &hf_netanalyzer_status_rx_err,
      { "MII RX_ER error", "netanalyzer.packetstatus.rx_er",
        FT_BOOLEAN, 8, NULL, MSK_RX_ERR,
        "RX_ER detected in frame", HFILL }
    },
    { &hf_netanalyzer_status_align_err,
      { "Alignment error", "netanalyzer.packetstatus.alignment_error",
        FT_BOOLEAN, 8, NULL, MSK_ALIGN_ERR,
        NULL, HFILL }
    },
    { &hf_netanalyzer_status_fcs,
      { "FCS error", "netanalyzer.packetstatus.fcs_error",
        FT_BOOLEAN, 8, NULL, MSK_FCS_ERROR,
        NULL, HFILL }
    },
    { &hf_netanalyzer_status_too_long,
      { "Frame too long", "netanalyzer.packetstatus.too_long",
        FT_BOOLEAN, 8, NULL, MSK_TOO_LONG,
        "Frame too long (capture truncated)", HFILL }
    },
    { &hf_netanalyzer_status_sfd_error,
      { "No valid SFD found", "netanalyzer.packetstatus.sfd_error",
        FT_BOOLEAN, 8, NULL, MSK_SFD_ERROR,
        "SDF error detected in frame", HFILL }
    },
    { &hf_netanalyzer_status_short_frame,
      { "Frame smaller 64 bytes", "netanalyzer.packetstatus.short_frame",
        FT_BOOLEAN, 8, NULL, MSK_SHORT_FRAME,
        NULL, HFILL }
    },
    { &hf_netanalyzer_status_short_preamble,
      { "Preamble shorter than 7 bytes", "netanalyzer.packetstatus.short_preamble",
        FT_BOOLEAN, 8, NULL, MSK_SHORT_PREAMBLE,
        NULL, HFILL }
    },
    { &hf_netanalyzer_status_long_preamble,
      { "Preamble longer than 7 bytes", "netanalyzer.packetstatus.long_preamble",
        FT_BOOLEAN, 8, NULL, MSK_LONG_PREAMBLE,
        NULL, HFILL }
    },
    { &hf_netanalyzer_buf,
      { "Buffer state entry", "netanalyzer.buffer",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "Info about reception buffer conditions", HFILL }
    },
    { &hf_netanalyzer_buf_state,
      { "Buffer state", "netanalyzer.buffer.state",
        FT_UINT8, BASE_DEC, VALS(buf_state_vals), 0x0,
        "State of receive buffers", HFILL }
    },
    { &hf_netanalyzer_buf_source,
      { "Buffer source", "netanalyzer.buffer.source",
        FT_UINT8, BASE_DEC, VALS(buf_source_vals), 0x0,
        "Source of buffer error", HFILL }
    },
    { &hf_netanalyzer_timetick,
      { "Time tick", "netanalyzer.timetick",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "Cyclic time tick of netANALYZER device", HFILL }
    },
  };

  static int *ett[] = {
    &ett_netanalyzer,
    &ett_netanalyzer_gpio,
    &ett_netanalyzer_status,
    &ett_netanalyzer_transparent,
    &ett_netanalyzer_buf,
  };

  static ei_register_info ei[] = {
    { &ei_netanalyzer_header_wrong, { "netanalyzer.header.wrong", PI_PROTOCOL, PI_ERROR, "Wrong netANALYZER header", EXPFILL }},
    { &ei_netanalyzer_gpio_def_none, { "netanalyzer.gpio_def_none", PI_MALFORMED, PI_ERROR, "No valid netANALYZER GPIO definition found", EXPFILL }},
    { &ei_netanalyzer_header_none, { "netanalyzer.header.none", PI_MALFORMED, PI_ERROR, "No netANALYZER header found", EXPFILL }},
    { &ei_netanalyzer_transparent_frame, { "netanalyzer.transparent_frame", PI_PROTOCOL, PI_NOTE, "This frame was captured in transparent mode", EXPFILL }},
    { &ei_netanalyzer_alignment_error, { "netanalyzer.alignment_error", PI_PROTOCOL, PI_WARN, "Displayed frame data contains additional nibble due to alignment error (upper nibble is not valid)", EXPFILL }},
    { &ei_netanalyzer_not_implemented,{ "netanalyzer.not_implemented", PI_PROTOCOL, PI_ERROR, "This feature is currently not implemented in Wireshark", EXPFILL } },
  };

  expert_module_t* expert_netanalyzer;

  proto_netanalyzer = proto_register_protocol (
    "netANALYZER",            /* name */
    "netANALYZER",            /* short name */
    "netanalyzer" );          /* abbrev */

  proto_register_field_array(proto_netanalyzer, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_netanalyzer = expert_register_protocol(proto_netanalyzer);
  expert_register_field_array(expert_netanalyzer, ei, array_length(ei));

  netana_handle             = register_dissector("netanalyzer",             dissect_netanalyzer,             proto_netanalyzer);
  netana_handle_transparent = register_dissector("netanalyzer_transparent", dissect_netanalyzer_transparent, proto_netanalyzer);
}


void proto_reg_handoff_netanalyzer(void)
{
  eth_dissector_handle  = find_dissector_add_dependency("eth_withfcs", proto_netanalyzer);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_NETANALYZER,             netana_handle);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_NETANALYZER_TRANSPARENT, netana_handle_transparent);
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
