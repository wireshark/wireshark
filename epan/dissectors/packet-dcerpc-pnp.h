/* packet-dcerpc-pnp.h
 * Routines for the pnp (Plug and Play) MSRPC interface
 * Copyright 2005 Jean-Baptiste Marchand <jbm@hsc.fr>
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

#ifndef __PACKET_DCERPC_PNP_H
#define __PACKET_DCERPC_PNP_H

/* MSRPC functions available in the pnp interface */

#define PNP_DISCONNECT 				0x00
#define PNP_CONNECT				0x01
#define PNP_GET_VERSION				0x02
#define PNP_GET_GLOBAL_STATE			0x03
#define PNP_INIT_DETECTION 			0x04
#define PNP_REPORT_LOGON			0x05
#define PNP_VALIDATE_DEVICE_INSTANCE		0x06
#define PNP_GET_ROOT_DEVICE_INSTANCE		0x07
#define PNP_GET_RELATED_DEVICE_INSTANCE		0x08
#define PNP_ENUMERATE_SUB_KEYS			0x09
#define PNP_GET_DEVICE_LIST			0x0a
#define PNP_GET_DEVICE_LIST_SIZE		0x0b
#define PNP_GET_DEPTH				0x0c
#define PNP_GET_DEVICE_REG_PROP			0x0d
#define PNP_SET_DEVICE_REG_PROP			0x0e
#define PNP_GET_CLASS_INSTANCE			0x0f
#define PNP_CREATE_KEY				0x10
#define PNP_DELETE_REGISTRY_KEY			0x11
#define PNP_GET_CLASS_COUNT			0x12
#define PNP_GET_CLASS_NAME			0x13
#define PNP_DELETE_CLASS_KEY			0x14
#define PNP_GET_INTERFACE_DEVICE_ALIAS		0x15
#define PNP_GET_INTERFACE_DEVICE_LIST		0x16
#define PNP_GET_INTERFACE_DEVICE_LIST_SIZE	0x17
#define PNP_REGISTER_DEVICE_CLASS_ASSOCIATION	0x18
#define PNP_UNREGISTER_DEVICE_CLASS_ASSOCIATION	0x19
#define PNP_GET_CLASS_REG_PROP			0x1a
#define PNP_SET_CLASS_REG_PROP			0x1b
#define PNP_CREATE_DEV_INST			0x1c
#define PNP_DEVICE_INSTANCE_ACTION		0x1d
#define PNP_GET_DEVICE_STATUS			0x1e
#define PNP_SET_DEVICE_PROBLEM			0x1f
#define PNP_DISABLE_DEV_INST			0x20
#define PNP_UNINSTALL_DEV_INST			0x21
#define PNP_ADD_ID				0x22
#define PNP_REGISTER_DRIVER			0x23
#define PNP_QUERY_REMOVE			0x24
#define PNP_REQUEST_DEVICE_EJECT		0x25
#define PNP_IS_DOCKSTATION_PRESENT		0x26
#define PNP_REQUEST_EJECT_PC			0x27
#define PNP_HW_PROT_FLAGS			0x28
#define PNP_GET_HW_PROT_INFO			0x29
#define PNP_ADD_EMPTY_LOG_CONF			0x2a
#define PNP_FREE_LOG_CONF			0x2b
#define PNP_GET_FIRST_LOG_CONF			0x2c
#define PNP_GET_NEXT_LOG_CONF			0x2d
#define PNP_GET_LOG_CONF_PRIORITY		0x2e
#define PNP_ADD_RES_DES				0x2f
#define PNP_FREE_RES_DES			0x30
#define PNP_GET_NEXT_RES_DES			0x31
#define PNP_GET_RES_DES_DATA			0x32
#define PNP_GET_RES_DES_DATA_SIZE		0x33
#define PNP_MODIFY_RES_DES			0x34
#define PNP_DETECT_RESOURCE_CONFLICT		0x35
#define PNP_QUERY_RES_CONFLICT			0x36
#define PNP_SET_HW_PROF				0x37
#define PNP_QUERY_ARBITRATOR_FREE_DATA		0x38
#define PNP_QUERY_ARBITRATOR_FREE_SIZE		0x39
#define PNP_RUN_DETECTION			0x3a
#define PNP_REGISTER_NOTIFICATION		0x3b
#define PNP_UNREGISTER_NOTIFICATION		0x3c
#define PNP_GET_CUSTOM_DEV_PROP			0x3d
#define PNP_GET_VERSION_INTERNAL		0x3e
#define PNP_GET_BLOCKED_DRIVER_INFO		0x3f
#define PNP_GET_SERVER_SIDE_DEV_INSTALL_FLAGS	0x40
#define PNP_GET_OBJECT_PROP_KEYS		0x41
#define PNP_GET_OBJECT_PROP			0x42
#define PNP_SET_OBJECT_PROP			0x43
#define PNP_INSTALL_DEV_INST			0x44
#define PNP_APPLY_POWER_SETTINGS		0x45
#define PNP_DRIVER_STORE_ADD_DRV_PKG		0x46
#define PNP_DRIVER_STORE_DEL_DRV_PKG		0x47
#define PNP_REGISTER_SRV_NOTIFICATION		0x48
#define PNP_SET_ACTIVE_SRV			0x49
#define PNP_DELETE_SERVICE_DEVICES		0x4a

#endif /* packet-dcerpc-pnp.h */
