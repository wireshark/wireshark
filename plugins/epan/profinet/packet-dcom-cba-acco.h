/* packet-dcom-cba-acco.h
 * Routines for DCOM CBA
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_DCERPC_DCOM_CBA_ACCO_H
#define __PACKET_DCERPC_DCOM_CBA_ACCO_H

typedef struct cba_pdev_s {
    GList           *ldevs;
    dcom_object_t   *object;
    int             first_packet;

    uint8_t         ip[4];
} cba_pdev_t;

typedef struct cba_ldev_s {
    GList           *provframes;
    GList           *consframes;
    GList           *provconns;
    GList           *consconns;
    dcom_object_t   *ldev_object;
    dcom_object_t   *acco_object;
    cba_pdev_t      *parent;
    int             first_packet;

    const char      *name;
} cba_ldev_t;


extern GList *cba_pdevs;

/**
 * @brief Finds a CBA device based on address and IPID.
 *
 * @param pinfo Packet information structure.
 * @param addr Address of the device.
 * @param ipid IP ID of the device.
 * @return cba_pdev_t* Pointer to the found CBA device, or NULL if not found.
 */
extern cba_pdev_t *
cba_pdev_find(packet_info *pinfo, const address *addr, e_guid_t *ipid);

/**
 * @brief Links a CBA device to a DCOM interface.
 *
 * @param pinfo Packet information structure.
 * @param pdev Pointer to the cba_pdev_t structure.
 * @param pdev_interf Pointer to the dcom_interface_t structure.
 */
extern void
cba_pdev_link(packet_info *pinfo, cba_pdev_t *pdev, dcom_interface_t *pdev_interf);

/**
 * @brief Adds a new physical device to the system.
 *
 * This function creates and initializes a new physical device based on the provided packet information and address.
 *
 * @param pinfo Packet information containing context about the current packet.
 * @param addr Address of the physical device to be added.
 * @return Pointer to the newly created cba_pdev_t structure if successful, NULL otherwise.
 */
extern cba_pdev_t *
cba_pdev_add(packet_info *pinfo, const address *addr);

/**
 * @brief Links a logical device to a DCOM interface.
 *
 * @param pinfo Packet information structure.
 * @param ldev Pointer to the cba_ldev_t structure.
 * @param ldev_interf Pointer to the dcom_interface_t structure.
 */
extern void
cba_ldev_link(packet_info *pinfo, cba_ldev_t *ldev, dcom_interface_t *ldev_interf);

/**
* @brief Links a logical device to an ACCO interface.
*
* @param pinfo Packet information structure.
* @param ldev Pointer to the cba_ldev_t structure representing the logical device.
* @param acco_interf Pointer to the dcom_interface_t structure representing the ACCO interface to link with the logical device.
*/
extern void
cba_ldev_link_acco(packet_info *pinfo, cba_ldev_t *ldev, dcom_interface_t *acco_interf);

/**
* @brief Finds a logical device based on address and IPID.
*
* @param pinfo Packet information structure.
* @param addr Address of the logical device.
* @param ipid IP ID of the logical device.
* @return cba_ldev_t* Pointer to the found logical device, or NULL if not found.
*/
extern cba_ldev_t *
cba_ldev_find(packet_info *pinfo, const address *addr, e_guid_t *ipid);

/**
 * @brief Adds a new logical device to the given physical device.
 *
 * Searches for an existing logical device with the specified name in the physical device's list of devices.
 * If found, returns the existing device; otherwise, creates a new logical device and adds it to the list.
 *
 * @param pinfo Pointer to the packet information structure.
 * @param pdev Pointer to the physical device structure.
 * @param name Name of the logical device to add or find.
 * @return Pointer to the logical device.
 */
extern cba_ldev_t *
cba_ldev_add(packet_info *pinfo, cba_pdev_t *pdev, const char *name);

#endif /* packet-dcerpc-dcom-cba-acco.h */
