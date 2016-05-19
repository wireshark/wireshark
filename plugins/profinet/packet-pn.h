/* packet-pn.h
 * Common functions for other PROFINET protocols like DCP, MRP, ...
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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

/*
 * Cyclic PNIO RTC1 Data Dissection:
 *
 * Added new structures to packet-pn.h to transfer the gained data of
 * packet-pn-dcp.c and packet-dcerpc-pn-io.c to packet-pn-rtc-one.c for
 * detailled dissection of cyclic PNIO RTC1 dataframes.
 *
 */

#define FRAME_ID_DCP_HELLO      0xfefc
#define FRAME_ID_DCP_GETORSET   0xfefd
#define FRAME_ID_DCP_IDENT_REQ  0xfefe
#define FRAME_ID_DCP_IDENT_RES  0xfeff


/* ---- Structures for pnio_rtc1 ---- */
extern int       proto_pn_dcp;
extern gboolean  pnio_ps_selection;  /* given by pnio preferences */

/* Structure for general station information */
typedef struct tagStationInfo {
    /* general information */
    gchar    *typeofstation;
    gchar    *nameofstation;
    guint16   u16Vendor_id;
    guint16   u16Device_id;
    /* frame structure */
    guint16   ioDataObjectNr;
    guint16   iocsNr;
    /* GSDfile station information */
    gboolean  gsdFound;
    gboolean  gsdPathLength;
    gchar    *gsdLocation;
    /* IOCS object data */
    wmem_list_t *iocs_data_in;
    wmem_list_t *iocs_data_out;
    /* IOData object data */
    wmem_list_t *ioobject_data_in;
    wmem_list_t *ioobject_data_out;
    /* Different ModuleIdentnumber */
    wmem_list_t *diff_module;
} stationInfo;

/* Structure for IOCS Frames */
typedef struct tagIocsObject {
    guint16    slotNr;
    guint16    subSlotNr;
    guint16    frameOffset;
} iocsObject;

/* Structure for IO Data Objects  */
typedef struct tagIoDataObject {
    guint16     slotNr;
    guint16     subSlotNr;
    guint32     moduleIdentNr;
    guint32     subModuleIdentNr;
    guint16     frameOffset;
    guint16     length;
    guint16     amountInGSDML;
    guint32     fParameterIndexNr;
    guint16     f_par_crc1;
    guint16     f_src_adr;
    guint16     f_dest_adr;
    gboolean    f_crc_seed;
    guint8      f_crc_len;
    address     srcAddr;
    address     dstAddr;
    gboolean    profisafeSupported;
    gboolean    discardIOXS;
    gchar      *moduleNameStr;
    tvbuff_t   *tvb_slot;
    tvbuff_t   *tvb_subslot;
    /* Status- or Controlbyte data*/
    guint8     last_sb_cb;
    guint8     lastToggleBit;
} ioDataObject;

/* Structure for Modules with different ModuleIdentnumber */
typedef struct tagModuleDiffInfo {
    guint16    slotNr;
    guint32    modulID;
} moduleDiffInfo;


extern void init_pn(int proto);
extern void init_pn_io_rtc1(int proto);

extern void init_pnio_rtc1_station(stationInfo *station_info);

extern int dissect_pn_uint8(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                  proto_tree *tree, int hfindex, guint8 *pdata);

extern int dissect_pn_uint16_ret_item(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
                       proto_tree *tree, int hfindex, guint16 *pdata, proto_item ** new_item);
extern int dissect_pn_uint16(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, int hfindex, guint16 *pdata);

extern int dissect_pn_uint32(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, int hfindex, guint32 *pdata);

extern int dissect_pn_int16(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, int hfindex, gint16 *pdata);

extern int dissect_pn_int32(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, int hfindex, gint32 *pdata);

extern int dissect_pn_oid(tvbuff_t *tvb, int offset, packet_info *pinfo,
                    proto_tree *tree, int hfindex, guint32 *pdata);

extern int dissect_pn_mac(tvbuff_t *tvb, int offset, packet_info *pinfo,
                    proto_tree *tree, int hfindex, guint8 *pdata);

extern int dissect_pn_ipv4(tvbuff_t *tvb, int offset, packet_info *pinfo,
                    proto_tree *tree, int hfindex, guint32 *pdata);

extern int dissect_pn_uuid(tvbuff_t *tvb, int offset, packet_info *pinfo,
                    proto_tree *tree, int hfindex, e_guid_t *uuid);

extern int dissect_pn_undecoded(tvbuff_t *tvb, int offset, packet_info *pinfo,
                    proto_tree *tree, guint32 length);

extern int dissect_pn_user_data(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                    proto_tree *tree, guint32 length, const char *text);

#define SUBST_DATA  1
#define FRAG_DATA   2

extern int dissect_pn_user_data_bytes(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                    proto_tree *tree, guint32 length, int iSelect);

extern int dissect_pn_malformed(tvbuff_t *tvb, int offset, packet_info *pinfo,
                    proto_tree *tree, guint32 length);

extern int dissect_pn_padding(tvbuff_t *tvb, int offset, packet_info *pinfo,
                    proto_tree *tree, int length);

extern int dissect_pn_align4(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

extern int dissect_PNIO_C_SDU_RTC1(tvbuff_t *tvb, int offset, packet_info *pinfo,
                    proto_tree *tree, guint8 *drep _U_);

extern void pn_append_info(packet_info *pinfo, proto_item *dcp_item, const char *text);

extern gboolean dissect_CSF_SDU_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
