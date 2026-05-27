/** @file
 *
 * Copyright 2018, Dirk Eibach, Guntermann & Drunck GmbH <dirk.eibach@gdsys.cc>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DPAUXMON_USER_H_
#define DPAUXMON_USER_H_

#include <linux/types.h>

/*
 * Generic Netlink Interface for DisplayPort AUX channel monitoring
 */

/**
 * @brief Netlink commands supported by the dpauxmon DisplayPort AUX channel monitor.
 */
enum dpauxmon_cmd {
    __DPAUXMON_CMD_UNSPEC,                       /**< Unspecified command; used to catch uninitialized or error cases */
    DPAUXMON_CMD_START,                          /**< Start AUX channel monitoring on the interface identified by DPAUXMON_ATTR_IFINDEX */
    DPAUXMON_CMD_STOP,                           /**< Stop AUX channel monitoring on the interface identified by DPAUXMON_ATTR_IFINDEX */
    DPAUXMON_CMD_DATA,                           /**< Deliver captured AUX channel data from the interface identified by DPAUXMON_ATTR_IFINDEX */

    /* keep last */
    __DPAUXMON_CMD_MAX,                          /**< Sentinel: one past the last valid command; do not use directly */
    DPAUXMON_CMD_MAX = __DPAUXMON_CMD_MAX - 1,   /**< Maximum valid command value */
};


/**
 * @brief Netlink attributes carried in dpauxmon messages.
 */
enum dpauxmon_attr {
    __DPAUXMON_ATTR_UNSPEC,                              /**< Unspecified attribute; used to catch uninitialized or error cases */
    DPAUXMON_ATTR_IFINDEX,                               /**< Index of the dpauxmon unit to operate on (NLA_U32) */
    DPAUXMON_ATTR_DATA,                                  /**< Raw AUX channel data payload (NLA_BINARY) */
    DPAUXMON_ATTR_FROM_SOURCE,                           /**< Flag indicating the payload was sent from the source (NLA_FLAG) */
    DPAUXMON_ATTR_TIMESTAMP,                             /**< Timestamp associated with the captured data payload (NLA_MSECS) */

    /* keep last */
    __DPAUXMON_ATTR_AFTER_LAST,                          /**< Sentinel: one past the last valid attribute; do not use directly */
    DPAUXMON_ATTR_MAX = __DPAUXMON_ATTR_AFTER_LAST - 1   /**< Maximum valid attribute value */
};

#endif
