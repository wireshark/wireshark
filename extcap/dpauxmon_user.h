/*
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

/*
 * enum dpauxmon_cmd - supported dpauxmon netlink commands
 *
 * @__DPAUXMON_CMD_UNSPEC: unspecified command to catch errors
 *
 * @DPAUXMON_CMD_START: start monitoring on %DPAUXMON_ATTR_IFINDEX
 * @DPAUXMON_CMD_STOP: stop monitoring on %DPAUXMON_ATTR_IFINDEX
 * @DPAUXMON_CMD_DATA: captured data from %DPAUXMON_ATTR_IFINDEX
 */
enum dpauxmon_cmd {
	__DPAUXMON_CMD_UNSPEC,
	DPAUXMON_CMD_START,
	DPAUXMON_CMD_STOP,
	DPAUXMON_CMD_DATA,

	/* keep last */
	__DPAUXMON_CMD_MAX,
	DPAUXMON_CMD_MAX = __DPAUXMON_CMD_MAX - 1,
};

/*
 * enum dpauxmon_attr - dpauxmon netlink attributes
 *
 * @__DPAUXMON_ATTR_UNSPEC: unspecified attribute to catch errors
 *
 * @DPAUXMON_ATTR_IFINDEX: index of dpauxmon unit to operate on
 * @DPAUXMON_ATTR_DATA: dpauxmon data payload
 * @DPAUXMON_ATTR_FROM_SOURCE: data payload is sent from source
 * @DPAUXMON_ATTR_TIMESTAMP: data payload is sent from source
 */
enum dpauxmon_attr {
	__DPAUXMON_ATTR_UNSPEC,
	DPAUXMON_ATTR_IFINDEX, /* NLA_U32 */
	DPAUXMON_ATTR_DATA, /* NLA_BINARY */
	DPAUXMON_ATTR_FROM_SOURCE, /* NLA_FLAG */
	DPAUXMON_ATTR_TIMESTAMP, /* NLA_MSECS */

	/* keep last */
	__DPAUXMON_ATTR_AFTER_LAST,
	DPAUXMON_ATTR_MAX = __DPAUXMON_ATTR_AFTER_LAST - 1
};

#endif
