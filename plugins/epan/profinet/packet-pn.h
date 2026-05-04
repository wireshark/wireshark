/* packet-pn.h
 * Common functions for other PROFINET protocols like DCP, MRP, ...
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Cyclic PNIO RTC1 Data Dissection:
 *
 * Added new structures to packet-pn.h to transfer the gained data of
 * packet-pn-dcp.c and packet-dcerpc-pn-io.c to packet-pn-rtc-one.c for
 * detailed dissection of cyclic PNIO RTC1 dataframes.
 *
 */

#define FRAME_ID_DCP_HELLO      0xfefc
#define FRAME_ID_DCP_GETORSET   0xfefd
#define FRAME_ID_DCP_IDENT_REQ  0xfefe
#define FRAME_ID_DCP_IDENT_RES  0xfeff


/* ---- Structures for pnio_rtc1 ---- */
extern int       proto_pn_dcp;
extern int proto_pn_io_apdu_status;
extern int proto_pn_io_time_aware_status;

extern bool pnio_ps_selection;  /* given by pnio preferences */

/* Structure for general station information */
typedef struct tagStationInfo {
    /* general information */
    char     *typeofstation;
    char     *nameofstation;
    uint16_t  u16Vendor_id;
    uint16_t  u16Device_id;
    /* frame structure */
    uint16_t  ioDataObjectNr_in;
    uint16_t  ioDataObjectNr_out;
    uint16_t  iocsNr_in;
    uint16_t  iocsNr_out;
    /* GSDfile station information */
    bool      gsdFound;
    bool      gsdPathLength;
    char     *gsdLocation;
    /* IOCS object data */
    wmem_list_t *iocs_data_in;
    wmem_list_t *iocs_data_out;
    /* IOData object data */
    wmem_list_t *ioobject_data_in;
    wmem_list_t *ioobject_data_out;
    /* Different ModuleIdentnumber */
    wmem_list_t *diff_module;
    /* Flag for the extraction of PNIO Objects without AR */
    bool filled_with_objects;
} stationInfo;

typedef struct tagApduStatusSwitch
{
    bool isRedundancyActive;
    address dl_dst;
    address dl_src;
}apduStatusSwitch;

/* Structure for IOCS Frames */
typedef struct tagIocsObject {
    uint16_t   slotNr;
    uint16_t   subSlotNr;
    uint16_t   frameOffset;
} iocsObject;

/* Structure for IO Data Objects  */
typedef struct tagIoDataObject {
    uint16_t    slotNr;
    uint16_t    subSlotNr;
    uint32_t    api;
    uint32_t    moduleIdentNr;
    uint32_t    subModuleIdentNr;
    uint16_t    frameOffset;
    uint16_t    length;
    uint16_t    amountInGSDML;
    uint32_t    fParameterIndexNr;
    uint16_t    f_par_crc1;
    uint16_t    f_src_adr;
    uint16_t    f_dest_adr;
    bool        f_crc_seed;
    uint8_t     f_crc_len;
    address     srcAddr;
    address     dstAddr;
    bool        profisafeSupported;
    bool        discardIOXS;
    char       *moduleNameStr;
    tvbuff_t   *tvb_slot;
    tvbuff_t   *tvb_subslot;
    /* Status- or Controlbyte data*/
    uint8_t    last_sb_cb;
    uint8_t    lastToggleBit;
} ioDataObject;

/* Structure for Modules with different ModuleIdentnumber */
typedef struct tagModuleDiffInfo {
    uint16_t   slotNr;
    uint32_t   modulID;
} moduleDiffInfo;

typedef struct tagARUUIDFrame {
    e_guid_t aruuid;
    uint32_t setupframe;
    uint32_t releaseframe;
    uint16_t outputframe;
    uint16_t inputframe;
} ARUUIDFrame;

extern wmem_list_t *aruuid_frame_setup_list;

/**
 * @brief Initialize PROFINET protocol dissector.
 *
 * @param proto Protocol identifier.
 */
extern void init_pn(int proto);

/**
 * @brief Initialize PN-IO RTC1 protocol dissector.
 *
 * @param proto Protocol identifier.
 */
extern void init_pn_io_rtc1(int proto);

/**
 * @brief Initialize PN-RSI protocol.
 *
 * @param proto Protocol identifier.
 */
extern void init_pn_rsi(int proto);

/**
 * @brief Initialize the RSI reassembly functionality.
 */
extern void pn_rsi_reassemble_init(void);

/**
 * @brief Initialize the PNIO RTC1 station information structure.
 *
 * @param station_info Pointer to the stationInfo structure to be initialized.
 */
extern void init_pnio_rtc1_station(stationInfo *station_info);

/**
 * @brief Dissects a 8-bit unsigned integer from the packet buffer.
 *
 * @param tvb The input buffer containing the packet data.
 * @param offset The current offset within the buffer to start dissecting.
 * @param pinfo Packet information structure.
 * @param tree Protocol tree for displaying the dissection results.
 * @param hfindex Field ID index for the new field.
 * @param pdata Pointer to store the dissected value.
 * @return The updated offset after dissecting the 8-bit unsigned integer.
 */
extern unsigned dissect_pn_uint8(tvbuff_t *tvb, unsigned offset, packet_info *pinfo,
                  proto_tree *tree, int hfindex, uint8_t *pdata);

/**
 * @brief Dissects a 16-bit unsigned integer from the packet buffer and adds it as a proto item.
 *
 * @param tvb The input buffer containing the packet data.
 * @param offset The current offset within the buffer to start dissecting.
 * @param pinfo Packet information structure.
 * @param tree Protocol tree for displaying the dissection results.
 * @param hfindex Field ID index for the new field.
 * @param pdata Pointer to store the dissected 16-bit unsigned integer value.
 * @param new_item Pointer to store the created proto item for the dissected field.
 * @return The updated offset after dissecting the 16-bit unsigned integer.
 */
extern unsigned dissect_pn_uint16_ret_item(tvbuff_t *tvb, unsigned offset, packet_info *pinfo _U_,
                       proto_tree *tree, int hfindex, uint16_t *pdata, proto_item ** new_item);

/**
 * @brief Dissects a 16-bit unsigned integer from the packet buffer.
 *
 * @param tvb The input buffer containing the packet data.
 * @param offset The starting offset within the buffer to begin dissection.
 * @param pinfo Packet information structure.
 * @param tree Protocol tree for displaying dissected data.
 * @param hfindex Field ID index for the new field.
 * @param pdata Pointer to store the dissected 16-bit unsigned integer value.
 * @return The number of bytes consumed during dissection.
 */
extern unsigned dissect_pn_uint16(tvbuff_t *tvb, unsigned offset, packet_info *pinfo,
                       proto_tree *tree, int hfindex, uint16_t *pdata);

/**
 * @brief Dissects a 16-bit integer from the packet buffer.
 *
 * @param tvb The input buffer containing the packet data.
 * @param offset The current offset within the buffer to start dissection.
 * @param pinfo Packet information structure.
 * @param tree Protocol tree for displaying dissected data.
 * @param hfindex Field ID index for the new field.
 * @param pdata Pointer to store the dissected 16-bit integer value.
 * @return The number of bytes consumed during dissection.
 */
extern unsigned dissect_pn_int16(tvbuff_t *tvb, unsigned offset, packet_info *pinfo,
                       proto_tree *tree, int hfindex, int16_t *pdata);

/**
 * @brief Dissects a PROFIBUS-DP OID (Object Identifier).
 *
 * @param tvb The TVB buffer containing the data.
 * @param offset The current offset within the TVB buffer.
 * @param pinfo Packet information structure.
 * @param tree Protocol tree for displaying the dissection.
 * @param hfindex Field ID index for the OID field.
 * @param pdata Pointer to store the parsed OID data.
 * @return The new offset after dissecting the OID.
 */
extern unsigned dissect_pn_oid(tvbuff_t *tvb, unsigned offset, packet_info *pinfo,
                    proto_tree *tree, int hfindex, uint32_t *pdata);

/**
 * @brief Dissects a PROFIBUS-DP MAC frame.
 *
 * @param tvb The TVB buffer containing the data to dissect.
 * @param offset The current offset within the TVB buffer.
 * @param pinfo Packet information structure.
 * @param tree Protocol tree for displaying the dissection results.
 * @param hfindex Index of the field to be used for display in the protocol tree.
 * @param pdata Pointer to a data buffer where additional data can be stored.
 * @return The new offset after dissecting the MAC frame.
 */
extern unsigned dissect_pn_mac(tvbuff_t *tvb, unsigned offset, packet_info *pinfo,
                    proto_tree *tree, int hfindex, uint8_t *pdata);

/**
 * @brief Dissects a PROFINET IPv4 packet.
 *
 * @param tvb The TVB containing the data to dissect.
 * @param offset The current offset within the TVB.
 * @param pinfo Packet information structure.
 * @param tree Protocol tree for displaying the dissection.
 * @param hfindex Field index for the protocol field.
 * @param pdata Pointer to store additional data.
 * @return The new offset after dissection.
 */
extern unsigned dissect_pn_ipv4(tvbuff_t *tvb, unsigned offset, packet_info *pinfo,
                    proto_tree *tree, int hfindex, uint32_t *pdata);

/**
 * @brief Dissects a UUID from the packet buffer.
 *
 * @param tvb The input buffer containing the packet data.
 * @param offset The starting offset within the buffer to begin dissection.
 * @param pinfo Packet information structure.
 * @param tree Protocol tree for adding dissected items.
 * @param hfindex Field identifier for the UUID.
 * @param uuid Pointer to store the dissected UUID.
 * @return The number of bytes consumed during dissection.
 */
extern unsigned dissect_pn_uuid(tvbuff_t *tvb, unsigned offset, packet_info *pinfo,
                    proto_tree *tree, int hfindex, e_guid_t *uuid);

/**
 * @brief "dissect" some undecoded bytes (with Expert warning)
 *
 * @param tvb The input buffer containing the packet data.
 * @param offset The current offset within the buffer to start dissecting.
 * @param pinfo Packet information structure.
 * @param tree Protocol tree for displaying the dissection results.
 * @param length Length of the data to be dissected in bytes.
 * @return The new offset after dissecting the undecoded bytes.
 */
extern unsigned dissect_pn_undecoded(tvbuff_t *tvb, unsigned offset, packet_info *pinfo,
                    proto_tree *tree, uint32_t length);

/**
 * @brief Dissects PN user data.
 *
 * @param tvb The TVB containing the packet data.
 * @param offset The current offset within the TVB.
 * @param pinfo Packet information (not used).
 * @param tree Protocol tree to add items to.
 * @param length Length of the data to dissect.
 * @param text Text associated with the data.
 * @return The new offset after dissection.
 */
extern unsigned dissect_pn_user_data(tvbuff_t *tvb, unsigned offset, packet_info *pinfo _U_,
                    proto_tree *tree, uint32_t length, const char *text);

/**
 * @brief Dissects PA Profile data within a packet.
 *
 * This function processes the PA Profile data, which includes an 8-bit status and either a float, an 8-bit integer, or a 16-bit integer.
 *
 * @param tvb The TVB buffer containing the packet data.
 * @param offset The current offset within the TVB buffer.
 * @param pinfo Packet information (not used).
 * @param tree Protocol tree to add items to.
 * @param length Length of the PA Profile data.
 * @param text Text associated with the PA Profile data (not used).
 * @return Updated offset after processing the PA Profile data.
 */
extern unsigned dissect_pn_pa_profile_data(tvbuff_t *tvb, unsigned offset, packet_info *pinfo _U_,
                    proto_tree *tree, uint32_t length, const char *text);

/**
 * @brief Dissects PN-IO blocks in a TVB buffer.
 *
 * @param tvb The TVB buffer containing the data to be dissected.
 * @param offset The current offset within the TVB buffer.
 * @param pinfo Packet information structure.
 * @param tree Protocol tree for displaying dissection results.
 * @param drep Data representation (byte order).
 * @return The updated offset after dissecting all blocks.
 */
extern unsigned dissect_blocks(tvbuff_t *tvb, unsigned offset,
                    packet_info *pinfo, proto_tree *tree, uint8_t *drep);

#define PDU_TYPE_REQ 0x05
#define PDU_TYPE_RSP 0x06

/**
 * @brief Dissects a PN-RSI blocks.
 *
 * @param tvb The TVB buffer containing the data to dissect.
 * @param offset The current offset within the TVB buffer.
 * @param pinfo Packet information structure.
 * @param tree Protocol tree for displaying the dissection results.
 * @param drep Data representation.
 * @param u32FOpnumOffsetOpnum Offset of operation number.
 * @param type Type of data to dissect.
 * @return The new offset after dissection.
 */
extern unsigned dissect_rsi_blocks(tvbuff_t* tvb, unsigned offset, packet_info* pinfo, proto_tree* tree, uint8_t* drep, uint32_t u32FOpnumOffsetOpnum, int type);

#define SUBST_DATA  1
#define FRAG_DATA   2

/**
 * @brief Dissects user data bytes in a PROFNET packet.
 *
 * @param tvb The TVB containing the packet data.
 * @param offset The current offset within the TVB.
 * @param pinfo Packet information (not used).
 * @param tree Protocol tree to add items to.
 * @param length Length of the data to dissect.
 * @param iSelect Selection flag indicating the type of data.
 * @return The new offset after dissection.
 */
extern unsigned dissect_pn_user_data_bytes(tvbuff_t *tvb, unsigned offset, packet_info *pinfo _U_,
                    proto_tree *tree, uint32_t length, int iSelect);

/**
 * @brief Dissects a malformed PROFINET packet.
 *
 * @param tvb The TVB buffer containing the packet data.
 * @param offset The current offset within the TVB buffer.
 * @param pinfo Packet information structure.
 * @param tree Protocol tree for displaying the dissection results.
 * @param length Length of the malformed data.
 * @return The new offset after dissection.
 */
extern unsigned dissect_pn_malformed(tvbuff_t *tvb, unsigned offset, packet_info *pinfo,
                    proto_tree *tree, uint32_t length);

/**
 * @brief Dissects PROFIBUS-DP padding.
 *
 * @param tvb The input buffer containing the packet data.
 * @param offset The current offset within the buffer to start dissection.
 * @param pinfo Packet information structure.
 * @param tree Protocol tree for displaying dissected data.
 * @param length Length of the padding.
 * @return The number of bytes consumed during dissection.
 */
extern unsigned dissect_pn_padding(tvbuff_t *tvb, unsigned offset, packet_info *pinfo,
                    proto_tree *tree, unsigned length);

/**
 * @brief Aligns the offset to a 4-byte boundary.
 *
 * @param tvb The TVB buffer containing the data.
 * @param offset The current offset within the TVB buffer.
 * @param pinfo Packet information structure.
 * @param tree Protocol tree for displaying the dissection.
 * @return The new offset after alignment.
 */
extern unsigned dissect_pn_align4(tvbuff_t *tvb, unsigned offset, packet_info *pinfo, proto_tree *tree);

/**
 * @brief Dissects the PNIO status information.
 *
 * @param tvb The TVB buffer containing the data to dissect.
 * @param offset The current offset within the TVB buffer.
 * @param pinfo Packet information structure.
 * @param tree Protocol tree for adding dissected items.
 * @param drep Data representation (endianness).
 * @return The new offset after dissection.
 */
extern unsigned dissect_PNIO_status(tvbuff_t *tvb, unsigned offset, packet_info *pinfo,
                    proto_tree *tree, uint8_t *drep);

 /**
  * @brief Dissects a PNIO C SDU RTC1 packet.
  *
  * @param tvb The TVB buffer containing the packet data.
  * @param offset The current offset within the TVB buffer.
  * @param pinfo Packet information structure.
  * @param tree Protocol tree to add dissected items to.
  * @param drep Data representation (not used).
  * @param frameid Frame identifier.
  * @return The new offset after dissection.
  */

extern unsigned dissect_PNIO_C_SDU_RTC1(tvbuff_t* tvb, unsigned offset, packet_info* pinfo,
                    proto_tree* tree, uint8_t* drep _U_, uint16_t frameid);

 /**
  * @brief Dissects a PN-IO RTC1 frame with security.
  *
  * @param tvb The TVB buffer containing the packet data.
  * @param offset The current offset within the TVB buffer.
  * @param pinfo Packet information structure.
  * @param tree Protocol tree to add dissected items to.
  * @param drep Data representation (not used).
  * @param frameid Frame identifier.
  * @return The new offset after dissection.
  */

extern unsigned dissect_PNIO_RTC1_with_security(tvbuff_t* tvb, unsigned offset, packet_info* pinfo,
                    proto_tree* tree, uint8_t* drep _U_, uint16_t frameid);

/**
 * @brief Dissects a RTC3 packet with security information.
 *
 * @param tvb The tvbuff_t containing the packet data.
 * @param offset The current offset within the tvbuff_t.
 * @param pinfo The packet_info structure for the packet.
 * @param tree The protocol tree to add items to.
 * @param drep The data representation (not used).
 * @param data Additional data (not used).
 * @return The new offset after dissection.
 */
extern unsigned dissect_RTC3_with_security(tvbuff_t* tvb, unsigned offset, packet_info* pinfo,
                    proto_tree* tree, uint8_t* drep _U_, void* data);

/**
 * @brief Dissects a PROFINET IO RSI (Remote Service Invocation) packet.
 *
 * @param tvb The TVB containing the data to dissect.
 * @param offset The current offset within the TVB.
 * @param pinfo Packet information structure.
 * @param tree Protocol tree for adding protocol items.
 * @param drep Data representation.
 * @return The new offset after dissection.
 */
extern unsigned dissect_PNIO_RSI(tvbuff_t *tvb, unsigned offset, packet_info *pinfo,
                    proto_tree *tree, uint8_t *drep);

/**
 * @brief Dissects a PNIO RSI with security.
 *
 * @param tvb The TVB buffer containing the data to dissect.
 * @param offset The current offset within the TVB buffer.
 * @param pinfo Packet information structure.
 * @param tree Protocol tree for displaying the dissection.
 * @param drep Data representation (endianness).
 * @return The new offset after dissection.
 */
extern unsigned dissect_PNIO_RSI_with_security(tvbuff_t* tvb, unsigned offset, packet_info* pinfo,
                    proto_tree* tree, uint8_t* drep);

/**
 * @brief Dissects a Security MetaData block in a PN-RT protocol.
 *
 * @param tvb The TVB buffer containing the packet data.
 * @param offset The current offset within the TVB buffer.
 * @param pinfo Packet information structure.
 * @param item Parent proto_item for this subtree.
 * @param tree Protocol tree to add items to.
 * @param drep Data representation (endianness).
 * @return The new offset after dissecting the block.
 */
extern unsigned dissect_SecurityMetaData_block(tvbuff_t* tvb, unsigned offset,
                    packet_info* pinfo, proto_item* item, proto_tree* tree, uint8_t* drep);

/**
 * @brief Dissects the SecurityChecksum field in a PROFIBUS-DP packet.
 *
 * @param tvb The TVB buffer containing the packet data.
 * @param offset The current offset within the TVB buffer.
 * @param tree The protocol tree to add items to.
 * @return The updated offset after dissecting the SecurityChecksum.
 */
extern unsigned dissect_SecurityChecksum(tvbuff_t* tvb, unsigned offset, proto_tree* tree);


/**
 * @brief Dissects a PN-IO RSI Instances block.
 *
 * @param tvb The TVB buffer containing the packet data.
 * @param offset The current offset within the TVB buffer.
 * @param pinfo Packet information structure.
 * @param tree Protocol tree for displaying dissected data.
 * @param item Unused parameter.
 * @param drep Data representation (endianness).
 * @param u8BlockVersionHigh High byte of block version.
 * @param u8BlockVersionLow Low byte of block version.
 * @return The updated offset after dissection.
 */
extern unsigned dissect_PDRsiInstances_block(tvbuff_t *tvb, unsigned offset,
                    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, uint8_t *drep, uint8_t u8BlockVersionHigh, uint8_t u8BlockVersionLow);

/**
 * @brief Appends information to packet info and protocol item.
 *
 * @param pinfo Pointer to packet_info structure.
 * @param dcp_item Pointer to protocol_item structure.
 * @param text Information text to append.
 */
extern void pn_append_info(packet_info *pinfo, proto_item *dcp_item, const char *text);

/**
 * @brief Initialize and append an ARUUID frame setup list.
 *
 * @param aruuid The ARUUID to be added.
 * @param setup The setup value for the ARUUID frame.
 */
extern void pn_init_append_aruuid_frame_setup_list(e_guid_t aruuid, uint32_t setup);

/**
 * @brief Finds the ARUUIDFrame setup frame for a given packet.
 *
 * @param pinfo The packet information structure.
 * @return ARUUIDFrame* Pointer to the found ARUUIDFrame, or NULL if not found.
 */
extern ARUUIDFrame* pn_find_aruuid_frame_setup(packet_info* pinfo);

/**
 * @brief Finds and updates DCP station information based on conversation data.
 *
 * Searches for DCP Station Info in the given conversation and updates the provided station_info structure accordingly.
 *
 * @param station_info Pointer to the stationInfo structure to be updated.
 * @param conversation Pointer to the conversation_t structure containing DCP station info.
 */
extern void pn_find_dcp_station_info(stationInfo* station_info, conversation_t* conversation);

/**
 * @brief Heuristic dissector for CSF SDU packets.
 *
 * This function attempts to dissect a CSF SDU packet based on its header information.
 *
 * @param tvb The TVB containing the packet data.
 * @param pinfo Packet information structure.
 * @param tree Protocol tree to add items to.
 * @param data Pointer to additional data, expected to be a pointer to a uint16_t FrameID.
 * @return True if the packet is dissected, false otherwise.
 */
extern bool dissect_CSF_SDU_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
