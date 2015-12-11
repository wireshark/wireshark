/* packet-tlv-cmctrl.c
 * Routines to Dissect TLV's for CM-Control Messages
 * Copyright 2010, Guido Reismueller <g.reismueller[AT]avm.de>
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

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>

#define CM_CTRL_MUTE 1
#define CM_CTRL_MUTE_TIMEOUT 2
#define CM_CTRL_REINIT 3
#define CM_CTRL_DISABLE_FWD 4
#define CM_CTRL_DS_EVENT 5
#define CM_CTRL_US_EVENT 6
#define CM_CTRL_EVENT 7

#define DS_EVENT_CH_ID 1
#define DS_EVENT_MASK 2

#define US_EVENT_CH_ID 1
#define US_EVENT_MASK 2

void proto_register_cmctrl_tlv(void);
void proto_reg_handoff_cmctrl_tlv(void);

/* Initialize the protocol and registered fields */
static int proto_cmctrl_tlv = -1;
static int hf_cmctrl_tlv_mute = -1;
static int hf_cmctrl_tlv_mute_timeout = -1;
static int hf_cmctrl_tlv_reinit = -1;
static int hf_cmctrl_tlv_disable_fwd = -1;
static int hf_cmctrl_tlv_ds_event = -1;
/* static int hf_cmctrl_tlv_us_event = -1; */
static int hf_cmctrl_tlv_event = -1;

static int hf_ds_event_ch_id = -1;
static int hf_ds_event_mask = -1;

static int hf_us_event_ch_id = -1;
static int hf_us_event_mask = -1;

/* Initialize the subtree pointers */
static gint ett_cmctrl_tlv = -1;
static gint ett_cmctrl_tlv_ds_event = -1;
static gint ett_cmctrl_tlv_us_event = -1;

/* Dissection */
static void
dissect_ds_event(tvbuff_t * tvb, proto_tree *tree, int start, guint16 len)
{
  guint8 type, length;
  proto_tree *event_tree;
  int pos = start;

  event_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_cmctrl_tlv_ds_event, NULL,
                         "Override Downstream Status Event Event Mask (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case DS_EVENT_CH_ID:
      if (length == 1)
        {
          proto_tree_add_item (event_tree, hf_ds_event_ch_id,
                               tvb, pos, length, ENC_BIG_ENDIAN);
        }
      else
        {
          THROW (ReportedBoundsError);
        }
          break;
        case DS_EVENT_MASK:
      if (length == 2)
        {
          proto_tree_add_item (event_tree, hf_ds_event_mask,
                               tvb, pos, length, ENC_NA);
        }
      else
        {
          THROW (ReportedBoundsError);
        }
          break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_us_event(tvbuff_t * tvb, proto_tree *tree, int start, guint16 len)
{
  guint8 type, length;
  proto_tree *event_tree;
  int pos = start;

  event_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_cmctrl_tlv_us_event, NULL,
                         "Override Upstream Status Enable Event Mask (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case US_EVENT_CH_ID:
      if (length == 1)
        {
          proto_tree_add_item (event_tree, hf_us_event_ch_id,
                               tvb, pos, length, ENC_BIG_ENDIAN);
        }
      else
        {
          THROW (ReportedBoundsError);
        }
          break;
        case US_EVENT_MASK:
      if (length == 2)
        {
          proto_tree_add_item (event_tree, hf_us_event_mask,
                               tvb, pos, length, ENC_NA);
        }
      else
        {
          THROW (ReportedBoundsError);
        }
          break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static int
dissect_cmctrl_tlv (tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *tlv_tree;
  int pos = 0;
  gint total_len;
  guint8 type, length;

  total_len = tvb_reported_length_remaining (tvb, 0);

  it =
    proto_tree_add_protocol_format (tree, proto_cmctrl_tlv, tvb, 0,
                                    total_len, "TLV Data");
  tlv_tree = proto_item_add_subtree (it, ett_cmctrl_tlv);

  while (pos < total_len)
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
        {
        case CM_CTRL_MUTE:
          if (length == 1)
            {
              proto_tree_add_item (tlv_tree, hf_cmctrl_tlv_mute,
                                   tvb, pos, length, ENC_BIG_ENDIAN);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CM_CTRL_MUTE_TIMEOUT:
          if (length == 4 || length == 1) /* response TLV always with len 1 */
            {
              proto_tree_add_item (tlv_tree, hf_cmctrl_tlv_mute_timeout,
                                   tvb, pos, length, ENC_BIG_ENDIAN);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CM_CTRL_REINIT:
          if (length == 1)
            {
              proto_tree_add_item (tlv_tree, hf_cmctrl_tlv_reinit,
                                   tvb, pos, length, ENC_BIG_ENDIAN);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CM_CTRL_DISABLE_FWD:
          if (length == 1)
            {
              proto_tree_add_item (tlv_tree, hf_cmctrl_tlv_disable_fwd,
                                   tvb, pos, length, ENC_BIG_ENDIAN);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;
        case CM_CTRL_DS_EVENT:
          if (length == 1)
            proto_tree_add_item (tlv_tree, hf_cmctrl_tlv_ds_event,
                                 tvb, pos, length, ENC_NA);
          else
            dissect_ds_event(tvb, tlv_tree, pos, length);
          break;
        case CM_CTRL_US_EVENT:
          if (length == 1)
            proto_tree_add_item (tlv_tree, hf_cmctrl_tlv_ds_event,
                                 tvb, pos, length, ENC_NA);
          else
            dissect_us_event(tvb, tlv_tree, pos, length);
          break;
        case CM_CTRL_EVENT:
          if (length == 2 || length == 1) /* response TLV always with len 1 */
            {
              proto_tree_add_item (tlv_tree, hf_cmctrl_tlv_event,
                                   tvb, pos, length, ENC_NA);
            }
          else
            {
              THROW (ReportedBoundsError);
            }
          break;

        } /* switch */
      pos = pos + length;
    } /* while */
    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void
proto_register_cmctrl_tlv (void)
{
  static hf_register_info hf[] = {
    {&hf_cmctrl_tlv_mute,
     {"1 Upstream Channel RF Mute", "cmctrl_tlv.mute",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Upstream Channel RF Mute", HFILL}
    },
    {&hf_cmctrl_tlv_mute_timeout,
     {"2 RF Mute Timeout Interval", "cmctrl_tlv.mute_timeout",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "RF Mute Timeout Interval", HFILL}
    },
    {&hf_cmctrl_tlv_reinit,
     {"3 CM Reinitialize", "cmctrl_tlv.reinit",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "CM Reinitialize", HFILL}
    },
    {&hf_cmctrl_tlv_disable_fwd,
     {"4 Disable Forwarding", "cmctrl_tlv.disable_fwd",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Disable Forwarding", HFILL}
    },
    {&hf_cmctrl_tlv_ds_event,
     {"5 Override Downstream Events", "cmctrl_tlv.ds_event",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Override Downstream Events", HFILL}
    },
    {&hf_ds_event_ch_id,
     {".1 Downstream Channel ID", "cmctrl_tlv.ds_event.chid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Downstream Channel ID", HFILL}
    },
    {&hf_ds_event_mask,
     {".2 Downstream Status Event Enable Bitmask", "cmctrl_tlv.ds_event.mask",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Downstream Status Event Enable Bitmask", HFILL}
    },
#if 0
    {&hf_cmctrl_tlv_us_event,
     {"6 Override Upstream Events", "cmctrl_tlv.us_event",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Override Downstream Events", HFILL}
    },
#endif
    {&hf_us_event_ch_id,
     {".1 Upstream Channel ID", "cmctrl_tlv.us_event.chid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Upstream Channel ID", HFILL}
    },
    {&hf_us_event_mask,
     {".2 Upstream Status Event Enable Bitmask", "cmctrl_tlv.us_event.mask",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Upstream Status Event Enable Bitmask", HFILL}
    },
    {&hf_cmctrl_tlv_event,
     {"7 Override Non-Channel-Specific Events", "cmctrl_tlv.event",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Override Non-Channel-Specific Events", HFILL}
    },
  };

  static gint *ett[] = {
    &ett_cmctrl_tlv,
    &ett_cmctrl_tlv_ds_event,
    &ett_cmctrl_tlv_us_event,
  };

  proto_cmctrl_tlv = proto_register_protocol ("DOCSIS CM-CTRL TLV's",
                                              "DOCSIS CM-CTRL TLVs", "cmctrl_tlv");

  proto_register_field_array (proto_cmctrl_tlv, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("cmctrl_tlv", dissect_cmctrl_tlv, proto_cmctrl_tlv);
}

void
proto_reg_handoff_cmctrl_tlv (void)
{
#if 0
  dissector_handle_t cmctrl_tlv_handle;

  cmctrl_tlv_handle = find_dissector ("cmctrl_tlv");

  dissector_add_uint ("docsis", 0xFE, cmctrl_tlv_handle);
#endif
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
