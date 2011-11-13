/* packet-ua.c
* Routines for UA (Universal Alcatel) packet dissection.
* Copyright 2011, Marek Tews <marek@trx.com.pl>
*
* $Id$
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998 Gerald Combs
*
* Copied from WHATEVER_FILE_YOU_USED (where "WHATEVER_FILE_YOU_USED"
* is a dissector file; if you just copied this from README.developer,
* don't bother with the "Copied from" - you don't even need to put
* in a "Copied from" if you copied an existing dissector, especially
* if the bulk of the code in the new dissector is your code)
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/strutil.h>


static void DissectNOE(tvbuff_t *pTvb, proto_tree *pRootUA);
static void DissectNOE_type(tvbuff_t *pTvb, proto_tree *pNoeItem);
static void DissectNOE_voicemode(tvbuff_t *pTvb, proto_tree *pNoeItem);
static void DissectNOE_callserver(tvbuff_t *pTvb, proto_tree *pNoeItem);
static void DissectNOE_ip(tvbuff_t *pTvb, proto_tree *pNoeItem);
static void DissectNOE_ip_startrtp(tvbuff_t *pTvb, proto_tree *pNoeItem);
static void DissectNOE_ip_startrtp_properties(tvbuff_t *pTvb, proto_tree *pNoeItem);

static void DissectTLV(tvbuff_t *pTvb, proto_tree *pNoeItem, gboolean bIsArrIndex);
static void DissectTLV_data(tvbuff_t *pTvb, proto_tree *pTlv, guint8 u8Property);

/*
* Here are the global variables associated with
* the various user definable characteristics of the dissection
*/

/* Define the UA proto */
static int proto_ua = -1;

/* Define many header fields for UA (Universal Alcatel Protocol) */
static int hf_noe = -1;
static int hf_noe_length = -1;
static int hf_noe_type = -1;
static int hf_noe_method = -1;
static int hf_noe_class = -1;
static int hf_noe_objid = -1;
static int hf_noe_event = -1;
static int hf_noe_keychar = -1;
static int hf_noe_action = -1;
static int hf_noe_reserved = -1;
static int hf_noe_property = -1;
static int hf_noe_id = -1;
static int hf_noe_size = -1;
static int hf_noe_local_port = -1;
static int hf_noe_remote_ip = -1;
static int hf_noe_remote_port = -1;
static int hf_noe_data = -1;
static int hf_noe_compressor = -1;
static int hf_noe_typeofservice = -1;
static int hf_noe_payloadconcat = -1;
static int hf_noe_voicemode = -1;

static int hf_tlv = -1;
static int hf_tlv_property = -1;
static int hf_tlv_arrindex = -1;
static int hf_tlv_propsize = -1;
static int hf_tlv_label = -1;
static int hf_tlv_data = -1;
static int hf_tlv_year = -1;
static int hf_tlv_number = -1;

/* Define the trees for UA (Universal Alcatel Protocol) */
static int ett_ua = -1;

static int ett_noe = -1;
static int ett_noe_property = -1;

static int ett_tlv = -1;
static int ett_tlv_sub = -1;


/************************************************************
* Value Strings
************************************************************/

/**
* NOE
*/
static const value_string szNoeType[] =
{
    { 0x00, "Unknown" },
    { 0x01, "HandsetOffHook" },
    { 0x02, "HandsetOnHook" },
    { 0x03, "DigitDialed" },
    { 0x13, "IP" },
    { 0x15, "CallServer" },
    { 0x20, "KeyPushed" },
    { 0x21, "LedCmd" },
    { 0x27, "WriteLine1" },
    { 0x28, "WriteLine2" },
    { 0x29, "VoiceMode" },
    { 0x31, "SetClockComd" },
    { 0x35, "CursorBlink" },
    { 0x38, "ClockTimerPosition" },
    { 0x3a, "Error_0x3a" },
    { 0x3d, "SideTone" },
    { 0x3f, "Mute" },
    { 0x46, "AllIconsOff" },
    { 0x47, "IconsCmd" },
    { 0x48, "AmplifiedHandset" },
    { 0x49, "DPIConfiguration" },
    { 0x4a, "AudioPaddedPath" },
    { 0x4f, "Error_0x4f" },
    { 0, NULL }
};

static const value_string szCallServerMethod[] =
{
    { 0x00, "Create" },
    { 0x01, "Delete" },
    { 0x02, "SetProperty" },
    { 0x04, "Notify" },
    { 0, NULL }
};

static const value_string szCallServerClass[] =
{
    { 1, "Terminal" },
    { 5, "Leds" },
    { 6, "Screen" },
    { 7, "Date" },
    { 8, "AOMV" },
    { 12, "CallState" },
    { 128, "FrameBox" },
    { 129, "TabBox" },
    { 130, "ListBox" },
    { 132, "TextBox" },
    { 133, "ActionBox" },
    { 136, "DataBox" },
    { 137, "TimerBox" },
    { 144, "AOMVBox" },
    { 145, "TelephonicBox" },
    { 146, "KeyboardContext" },
    { 151, "TelephonicBoxItem" },
    { 158, "HeaderBox" },
    { 0, NULL }
};

static const value_string szCallServerEvent[] =
{
    { 2, "KeyPress" },
    { 4, "KeyShortPress" },
    { 6, "OnHook" },
    { 7, "OffHook" },
    { 128, "TabBox" },
    { 133, "ActionBox" },
    { 152, "DialogBoxDismissed" },
    { 0, NULL }
};

static const value_string szStartRtpPropID[] =
{
    { 0x00, "LocalUDPPort" },
    { 0x01, "RemoteIP" },
    { 0x02, "RemoteUDPPort" },
    { 0x03, "TypeOfService" },
    { 0x04, "Payload" },
    { 0x05, "PayloadConcatenation" }, /* in ms */
    { 0x06, "EchoCancelationEnabler" },
    { 0x07, "SilenceCompression" },
    { 0x08, "_802_1QUserPriority" },
    { 0x0A, "PostFiltering" },
    { 0x0B, "HighPassFilter" },
    { 0, NULL }
};

static const value_string szStartRtpPayload[] =
{
    { 0, "G.711 A-law" },
    { 1, "G.711 mu-law" },
    { 2, "G.723.1 5.3 kbps" },
    { 3, "G.723.1 6.3 kbps" },
    { 0x11, "G.729A 8kbps"},
    { 0, NULL }
};

static const value_string szNoeAction[] =
{
    { 0x01, "Start RTP" },
    { 0x02, "Stop RTP" },
    { 0, NULL }
};

static const value_string szNoeVoiceMode[] =
{
    { 0x10, "Disable" },
    { 0x11, "Handset" },
    { 0x13, "Speaker" },
    { 0, NULL }
};

/**
* TLV PROPERTY
*/
static const value_string szTlvProperty[] =
{
    { 8, "Count" },
    { 11, "NavigatorOwnerShip" },
    { 15, "NumpadEvent" },
    { 16, "Format_16" },
    { 18, "W" },
    { 19, "Hour" },
    { 24, "Year" },
    { 25, "Month" },
    { 26, "Day" },
    { 27, "Minutes" },
    { 28, "Seconds" },
    { 36, "AnchorID" },
    { 39, "Y" },
    { 40, "Visible" },
    { 42, "FontID" },
    { 44, "HAlign" },
    { 54, "Icon_54" },
    { 55, "Label" },
    { 56, "Value" },
    { 61, "Focus" },
    { 62, "State_62" },
    { 63, "Format_63" },
    { 76, "VSplit" },
    { 78, "RealCount" },
    { 79, "Start" },
    { 95, "_95" },
    { 131, "Key Ownership" },
    { 134, "Mode" },
    { 135, "Color" },
    { 137, "Icon_137" },
    { 138, "Label_138" },
    { 141, "State_141" },
    { 142, "Name" },
    { 143, "Number" },
    { 147, "Today" },
    { 148, "Tomorrow" },
    { 0, NULL }
};

/************************************************************
* Check whether it can be protocol data
************************************************************/
gboolean is_ua(tvbuff_t *tvb)
{
    gint nLen, iOffs;
    gint nNoeLen;

    nLen = tvb_length(tvb);
    for(iOffs = 0; iOffs < nLen; )
    {
        nNoeLen = tvb_get_letohs(tvb, iOffs) +2;
        if(nNoeLen > nLen -iOffs)
            return FALSE;
        iOffs += nNoeLen;
    }
    return TRUE;
}

/************************************************************
* Dissectors
************************************************************/

/*
* DissectUA - The dissector for UA (Universal Alcatel Protocol)
*/
static int DissectUA(tvbuff_t *pTvb, packet_info *pInfo, proto_tree *pTree)
{
    gint nLen, iOffs;
    guint16 nNoeLen;
    proto_item *pRootUA;
    proto_tree *pSubTreeUA;
    tvbuff_t *pTvbNoe;

    /* Check whether it can be protocol data */
    if(!is_ua(pTvb))
        return 0;

    /* INFO column */
    if(check_col(pInfo->cinfo, COL_INFO))
        col_append_str(pInfo->cinfo, COL_INFO, " - UA");

    nLen = tvb_length(pTvb);
    if(pTree)
    {
        /* root element "UA Protocol, ..." */
        pRootUA = proto_tree_add_item(pTree, proto_ua, pTvb, 0, -1, ENC_NA);
        pSubTreeUA = proto_item_add_subtree(pRootUA, ett_ua);

        /* NOE items */
        for(iOffs = 0; iOffs < nLen; )
        {
            nNoeLen = tvb_get_letohs(pTvb, iOffs);
            nNoeLen += 2;

            pTvbNoe = tvb_new_subset(pTvb, iOffs, nNoeLen, nNoeLen);
            DissectNOE(pTvbNoe, pSubTreeUA);

            iOffs += nNoeLen;
        }
    }

    return nLen;
}


/**********************************************
* NOE section
***********************************************
Noe
NoeVoiceMode
NoeMute
NoeIP
NoeIPStartRTP
NoeCallServer
NoeCallServerCreate
NoeCallServerSetProperty
NoeCallServerNotify
NoeCallServerNotifyKeyPress
NoeCallServerNotifyKeyShortPress
***********************************************/
static void DissectNOE(tvbuff_t *pTvb, proto_tree *pRootUA)
{
    proto_item *pNoeItem = proto_tree_add_item(pRootUA, hf_noe, pTvb, 0, -1, ENC_NA);
    if(pNoeItem)
    {
        proto_tree* pSubTreeNOE;

        pSubTreeNOE = proto_item_add_subtree(pNoeItem, ett_noe);
        proto_tree_add_item(pSubTreeNOE, hf_noe_length, pTvb, 0, 2, ENC_LITTLE_ENDIAN);
        DissectNOE_type(tvb_new_subset_remaining(pTvb, 2), pSubTreeNOE);
    }
}

static void DissectNOE_type(tvbuff_t *pTvb, proto_tree *pNoeItem)
{
    proto_item_append_text(pNoeItem, ": %s", val_to_str(tvb_get_guint8(pTvb, 0), szNoeType, "Unknown"));
    proto_tree_add_item(pNoeItem, hf_noe_type, pTvb, 0, 1, ENC_NA);

    switch(tvb_get_guint8(pTvb, 0))
    {
    case 0x13: /*IP*/
        {
            DissectNOE_ip(tvb_new_subset_remaining(pTvb, 1), pNoeItem);
            break;
        }
    case 0x15: /*CallServer*/
        {
            DissectNOE_callserver(tvb_new_subset_remaining(pTvb, 1), pNoeItem);
            break;
        }
    case 0x29: /*VoiceMode*/
        {
            DissectNOE_voicemode(tvb_new_subset_remaining(pTvb, 1), pNoeItem);
            break;
        }
    }
}

static void DissectNOE_voicemode(tvbuff_t *pTvb, proto_tree *pNoeItem)
{
    proto_tree_add_item(pNoeItem, hf_noe_voicemode, pTvb, 0, 1, ENC_NA);
    if(tvb_length(pTvb) > 1)
        proto_tree_add_item(pNoeItem, hf_noe_data, pTvb, 1, -1, ENC_NA);
}

static void DissectNOE_callserver(tvbuff_t *pTvb, proto_tree *pNoeItem)
{
    tvbuff_t *pTvbTlv;

    gint nLen;
    guint8 u8Method;

    nLen = tvb_length(pTvb);
    u8Method = tvb_get_guint8(pTvb, 0);

    proto_item_append_text(pNoeItem, ", %s", val_to_str(u8Method, szCallServerMethod, "Unknown"));
    proto_tree_add_item(pNoeItem, hf_noe_method, pTvb, 0, 1, ENC_NA);

    switch(u8Method)
    {
    case 0x00: /*Create*/
    case 0x01: /*Delete*/
    case 0x02: /*SetProperty*/
        {
            guint8 u8Class; gint iOffs;

            u8Class = tvb_get_guint8(pTvb, 1);
            proto_item_append_text(pNoeItem, ", %s", val_to_str(u8Class, szCallServerClass, "Unknown"));
            proto_tree_add_item(pNoeItem, hf_noe_class, pTvb, 1, 1, ENC_NA);

            iOffs = 2;
            if(u8Class >= 100)
            {
                proto_item_append_text(pNoeItem, ", Id(0x%04x)", tvb_get_ntohs(pTvb, 2));
                proto_tree_add_item(pNoeItem, hf_noe_objid, pTvb, 2, 2, ENC_LITTLE_ENDIAN);
                iOffs += 2;
            }

            /* TLV items */
            for(; iOffs < nLen; )
            {
                guint8 nTlvLen, nTlvProperty; gboolean bIsArrIndex;

                nTlvProperty = tvb_get_guint8(pTvb, iOffs);
                /* for property of more than 100 and equal 120 before the field is still arrindex propsize */
                if(nTlvProperty < 100 || nTlvProperty == 120)
                {
                    nTlvLen = tvb_get_guint8(pTvb, iOffs+1);
                    nTlvLen += 2;
                    bIsArrIndex = FALSE;
                }
                else
                {
                    nTlvLen = tvb_get_guint8(pTvb, iOffs+2);
                    nTlvLen += 3;
                    bIsArrIndex = TRUE;
                }
                pTvbTlv = tvb_new_subset(pTvb, iOffs, nTlvLen, nTlvLen);
                DissectTLV(pTvbTlv, pNoeItem, bIsArrIndex);

                iOffs += nTlvLen;
            }
            break;
        }
    case 0x04: /*Notify*/
        {
            guint8 u8Event;

            u8Event = tvb_get_guint8(pTvb, 1);
            proto_tree_add_item(pNoeItem, hf_noe_event, pTvb, 1, 1, ENC_NA);

            switch(u8Event)
            {
            case 2: /*KeyPress*/
                {
                    proto_tree_add_item(pNoeItem, hf_noe_keychar, pTvb, 2, -1, ENC_NA);
                    break;
                }
            case 4: /*KeyShortPress*/
                {
                    proto_tree_add_item(pNoeItem, hf_noe_keychar, pTvb, 2, 2, ENC_NA);
                    break;
                }
            }
            break;
        }
    }
}

static void DissectNOE_ip(tvbuff_t *pTvb, proto_tree *pNoeItem)
{
    guint8 u8Action;

    /* Action */
    u8Action = tvb_get_guint8(pTvb, 0);
    proto_item_append_text(pNoeItem, " %s", val_to_str(u8Action, szNoeAction, "Unknown"));
    proto_tree_add_item(pNoeItem, hf_noe_action, pTvb, 0, 1, ENC_NA);

    switch(u8Action)
    {
    case 0x01: /*Start RTP*/
        {
            DissectNOE_ip_startrtp(tvb_new_subset_remaining(pTvb, 1), pNoeItem);
            break;
        }
    case 0x02: /*Stop RTP*/
        {
            break;
        }
    }
}

static void DissectNOE_ip_startrtp(tvbuff_t *pTvb, proto_tree *pNoeItem)
{
    gint nLen, iOffs;
    nLen = tvb_length(pTvb);

    /*Reserved*/
    proto_tree_add_item(pNoeItem, hf_noe_reserved, pTvb, 0, 1, ENC_NA);

    /*Properties*/
    for(iOffs = 1; iOffs < nLen; )
    {
        guint8 u8PropSize;
        tvbuff_t *pTvbTlv;

        u8PropSize = tvb_get_guint8(pTvb, iOffs+1) +2;
        pTvbTlv = tvb_new_subset(pTvb, iOffs, u8PropSize, u8PropSize);

        DissectNOE_ip_startrtp_properties(pTvbTlv, pNoeItem);
        iOffs += u8PropSize;
    }
}

static void DissectNOE_ip_startrtp_properties(tvbuff_t *pTvb, proto_tree *pNoeItem)
{
    proto_item *pProp;

    pProp = proto_tree_add_item(pNoeItem, hf_noe_property, pTvb, 0, -1, ENC_NA);
    if(pProp)
    {
        guint8 u8ID, u8Size;
        proto_tree* pSubTreeProp;

        pSubTreeProp = proto_item_add_subtree(pProp, ett_noe_property);
        /*ID*/
        u8ID = tvb_get_guint8(pTvb, 0);
        proto_item_append_text(pProp, " - %25s", val_to_str(u8ID, szStartRtpPropID, "Unknown"));
        proto_tree_add_item(pSubTreeProp, hf_noe_id, pTvb, 0, 1, ENC_NA);

        /*SIZE*/
        u8Size = tvb_get_guint8(pTvb, 1);
        proto_tree_add_item(pSubTreeProp, hf_noe_size, pTvb, 1, 1, ENC_NA);

        /*data*/
        switch(u8ID)
        {
        default:
            {
                proto_item_append_text(pProp, ": %s", tvb_bytes_to_str(pTvb, 2, u8Size));
                proto_tree_add_item(pSubTreeProp, hf_noe_data, pTvb, 2, -1, ENC_NA);
                break;
            }
        case 0x00: /*LocalUDPPort*/
            {
                proto_item_append_text(pProp, ": %u", tvb_get_ntohs(pTvb, 2));
                proto_tree_add_item(pSubTreeProp, hf_noe_local_port, pTvb, 2, -1, ENC_LITTLE_ENDIAN);
                break;
            }
        case 0x01: /*RemoteIP*/
            {
                proto_item_append_text(pProp, ": %s", tvb_ip_to_str(pTvb, 2));
                proto_tree_add_item(pSubTreeProp, hf_noe_remote_ip, pTvb, 2, -1, ENC_NA);
                break;
            }
        case 0x02: /*RemoteUDPPort*/
            {
                proto_item_append_text(pProp, ": %u", tvb_get_ntohs(pTvb, 2));
                proto_tree_add_item(pSubTreeProp, hf_noe_remote_port, pTvb, 2, -1, ENC_LITTLE_ENDIAN);
                break;
            }
        case 0x03: /*TypeOfService*/
            {
                proto_item_append_text(pProp, ": %u", tvb_get_guint8(pTvb, 2));
                proto_tree_add_item(pSubTreeProp, hf_noe_typeofservice, pTvb, 2, -1, ENC_NA);
                break;
            }
        case 0x04: /*Payload*/
            {
                proto_item_append_text(pProp, ": %s", val_to_str(tvb_get_guint8(pTvb, 2), szStartRtpPayload, "Unknown"));
                proto_tree_add_item(pSubTreeProp, hf_noe_compressor, pTvb, 2, -1, ENC_NA);
                break;
            }
        case 0x05: /*PayloadConcatenation*/
            {
                proto_item_append_text(pProp, ": %u ms", tvb_get_guint8(pTvb, 2));
                proto_tree_add_item(pSubTreeProp, hf_noe_payloadconcat, pTvb, 2, -1, ENC_NA);
                break;
            }
        }
    }
}

/***********************************************
* TLV section
***********************************************/
static void DissectTLV(tvbuff_t *pTvb, proto_tree *pNoeItem, gboolean bIsArrIndex)
{
    proto_item *pTlv;

    pTlv = proto_tree_add_item(pNoeItem, hf_tlv, pTvb, 0, -1, ENC_NA);
    if(pTlv)
    {
        gint iOffs;
        guint8 u8Property, u8PropSize;
        proto_tree* pSubTreeTLV;

        iOffs = 0;
        pSubTreeTLV = proto_item_add_subtree(pTlv, ett_tlv);
        u8Property = tvb_get_guint8(pTvb, iOffs);
        proto_item_append_text(pTlv, "%u %s ", u8Property, val_to_str(u8Property, szTlvProperty, "Unknown"));
        proto_tree_add_item(pSubTreeTLV, hf_tlv_property, pTvb, iOffs++, 1, ENC_NA);

        if(bIsArrIndex)
            proto_tree_add_item(pTlv, hf_tlv_arrindex, pTvb, iOffs++, 1, ENC_NA);

        u8PropSize = tvb_get_guint8(pTvb, iOffs);
        proto_tree_add_item(pSubTreeTLV, hf_tlv_propsize, pTvb, iOffs++, 1, ENC_NA);

        if(u8PropSize > 0)
            DissectTLV_data(tvb_new_subset(pTvb, iOffs, u8PropSize, u8PropSize), pSubTreeTLV, u8Property);
    }
}

/* TLV DATA */
static void DissectTLV_data(tvbuff_t *pTvb, proto_tree *pTlv, guint8 u8Property)
{
    proto_tree* pNoeItem;
    switch(u8Property)
    {
    default:
        {
            proto_item_append_text(pTlv, "%s", tvb_bytes_to_str(pTvb, 0, tvb_length(pTvb)));
            proto_tree_add_item(pTlv, hf_tlv_data, pTvb, 0, -1, ENC_NA);
            break;
        }

    case 24: /*Year*/
        {
            proto_item_append_text(pTlv, "%u", tvb_get_ntohs(pTvb, 0));
            proto_tree_add_item(pTlv, hf_tlv_year, pTvb, 0, 2, ENC_BIG_ENDIAN);
            break;
        }

    case 55: /*Label*/
    case 138: /*Label_138*/
        {
            proto_item_append_text(pTlv, "'%s'", tvb_get_string(pTvb, 0, tvb_length(pTvb)));
            proto_tree_add_item(pTlv, hf_tlv_label, pTvb, 0, -1, ENC_ASCII|ENC_NA);

            /* append text on NOE level */
            pNoeItem = proto_item_get_parent(pTlv);
            proto_item_append_text(pNoeItem, ", Label='%s'", tvb_get_string(pTvb, 0, tvb_length(pTvb)));
            break;
        }

    case 143: /*Phone number*/
        {
            proto_item_append_text(pTlv, "%s", tvb_get_string(pTvb, 0, tvb_length(pTvb)));
            proto_tree_add_item(pTlv, hf_tlv_number, pTvb, 0, -1, ENC_NA);
            break;
        }

    case 147: /*Today*/
    case 148: /*Tomorrow*/
        {
            proto_item_append_text(pTlv, "'%s'", tvb_get_string(pTvb, 0, tvb_length(pTvb)));
            proto_tree_add_item(pTlv, hf_tlv_data, pTvb, 0, -1, ENC_NA);
            break;
        }
    }
}



/* Register all the bits needed by the filtering engine */
void proto_register_ua(void)
{
    static hf_register_info hf[] =
    {
        { &hf_noe, { "NOE", "ua.noe", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_noe_length, { "Length", "ua.noe.length", FT_UINT16, BASE_DEC, NULL, 0x0, "NOE item length (without 2 bytes containing the length)", HFILL }},
        { &hf_noe_type, { "Type", "ua.noe.type", FT_UINT8, BASE_DEC, VALS(szNoeType), 0x0, "NOE item type", HFILL }},
        { &hf_noe_method, { "Method", "ua.noe.method", FT_UINT8, BASE_DEC, VALS(szCallServerMethod), 0x0, "Call Server method", HFILL }},
        { &hf_noe_class, { "Class", "ua.noe.class", FT_UINT8, BASE_DEC, VALS(szCallServerClass), 0x0, "Call Server class", HFILL }},
        { &hf_noe_objid, { "ObjectID", "ua.noe.objid", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, "Call Server object id", HFILL }},
        { &hf_noe_event, { "Event", "ua.noe.event", FT_UINT8, BASE_DEC, VALS(szCallServerEvent), 0x0, "Call Server event", HFILL }},
        { &hf_noe_keychar, { "KeyChar", "ua.noe.event.keychar", FT_BYTES, BASE_NONE, NULL, 0x0, "Event key char", HFILL }},
        { &hf_noe_voicemode, { "VoiceMode", "ua.noe.voicemode", FT_UINT8, BASE_DEC, VALS(szNoeVoiceMode), 0x0, NULL, HFILL }},

        { &hf_noe_action, { "Action", "ua.noe.action", FT_UINT8, BASE_DEC, VALS(szNoeAction), 0x0, "IP action", HFILL }},
        { &hf_noe_reserved, { "Reserved", "ua.noe.action.startrtp.reserved", FT_UINT8, BASE_DEC, NULL, 0x0, "IP start rtp reserved", HFILL }},
        { &hf_noe_property, { "Property", "ua.noe.action.startrtp.property", FT_NONE, BASE_NONE, NULL, 0x0, "IP property", HFILL }},
        { &hf_noe_id, { "ID", "ua.noe.action.startrtp.property.id", FT_UINT8, BASE_DEC, VALS(szStartRtpPropID), 0x0, "IP property id", HFILL }},
        { &hf_noe_size, { "Size", "ua.noe.action.startrtp.property.size", FT_UINT8, BASE_DEC, NULL, 0x0, "IP property size", HFILL }},
        { &hf_noe_data, { "Data", "ua.noe.action.startrtp.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_noe_local_port, { "LocalPort", "ua.noe.action.startrtp.localport", FT_UINT16, BASE_DEC, NULL, 0x0, "IP start rtp property localport", HFILL }},
        { &hf_noe_remote_ip, { "RemoteIP", "ua.noe.action.startrtp.remoteip", FT_IPv4, BASE_NONE, NULL, 0x0, "IP start rtp property remote ipv4", HFILL }},
        { &hf_noe_remote_port, { "RemotePort", "ua.noe.action.startrtp.remoteport", FT_UINT16, BASE_DEC, NULL, 0x0, "IP start rtp property remoteport", HFILL }},
        { &hf_noe_compressor, { "Payload", "ua.noe.action.startrtp.payload", FT_UINT8, BASE_DEC, VALS(szStartRtpPayload), 0x0, "IP start rtp property payload", HFILL }},
        { &hf_noe_typeofservice,{ "TypeOfService", "ua.noe.action.startrtp.typeofservice", FT_UINT8, BASE_DEC, NULL, 0x0, "IP start rtp property type of service", HFILL }},
        { &hf_noe_payloadconcat,{ "Payld Concat", "ua.noe.action.startrtp.payldconcat", FT_UINT8, BASE_DEC, NULL, 0x0, "IP start rtp property payload concatenation (in ms)", HFILL }},

        { &hf_tlv, { "TLV", "ua.noe.tlv", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_tlv_property, { "Property", "ua.noe.tlv.property", FT_UINT8, BASE_DEC, VALS(szTlvProperty), 0x0, "TLV property", HFILL }},
        { &hf_tlv_arrindex, { "ArrIndex", "ua.noe.tlv.arrindex", FT_UINT8, BASE_DEC, NULL, 0x0, "TLV array index", HFILL }},
        { &hf_tlv_propsize, { "PropSize", "ua.noe.tlv.propsize", FT_UINT8, BASE_DEC, NULL, 0x0, "TLV property size", HFILL }},
        { &hf_tlv_data, { "Data", "ua.noe.tlv.data", FT_BYTES, BASE_NONE, NULL, 0x0, "TLV data", HFILL }},
        { &hf_tlv_label, { "Label", "ua.noe.tlv.label", FT_STRING, BASE_NONE, NULL, 0x0, "TLV label", HFILL }},
        { &hf_tlv_year, { "Year", "ua.noe.tlv.year", FT_UINT16, BASE_DEC, NULL, 0x0, "TLV year", HFILL }},
        { &hf_tlv_number, { "Number", "ua.noe.tlv.number", FT_STRING, BASE_NONE, NULL, 0x0, "TLV remote phone number", HFILL }},
    };
    static gint *ett[] =
    {
        &ett_ua,
        &ett_noe,
        &ett_noe_property,
        &ett_tlv,
        &ett_tlv_sub,
    };

    proto_ua = proto_register_protocol("UA Protocol (Universal Alcatel Protocol)", "UA", "ua");
    proto_register_field_array(proto_ua, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


/* The registration hand-off routine is called at startup */
void proto_reg_handoff_ua(void)
{
    dissector_handle_t hDis = new_create_dissector_handle(DissectUA, proto_ua);
    dissector_add_uint("uaudp.opcode", 7, hDis);
}
/*
* Editor modelines - http://www.wireshark.org/tools/modelines.html
*
* Local variables:
* c-basic-offset: 4
* tab-width: 8
* indent-tabs-mode: nil
* End:
*
* ex: set shiftwidth=4 tabstop=8 expandtab:
* :indentSize=4:tabSize=8:noTabs=true:
*/
