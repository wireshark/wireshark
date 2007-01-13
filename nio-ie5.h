/*
 * Copyright (c) 2000, Red Hat, Inc.
 *
 *     This program is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation; either version 2 of the License, or
 *     (at your option) any later version.
 *
 *     A copy of the GNU General Public License can be found at
 *     http://www.gnu.org/
 *
 * Written by DJ Delorie <dj@cygnus.com>
 * Modified by Ulf Lamping to meet Wireshark use
 *
 */

#ifndef SETUP_NIO_IE5_H
#define SETUP_NIO_IE5_H

/* see nio-ie5.c */

typedef struct netio_ie5_s {
    HINTERNET connection;
} netio_ie5_t;

netio_ie5_t * netio_ie5_connect (char const *url);
void netio_ie5_disconnect (netio_ie5_t * netio_e5_conn);
int netio_ie5_ok (netio_ie5_t * netio_e5_conn);
int netio_ie5_read (netio_ie5_t * netio_e5_conn, char *buf, int nbytes);
void netio_ie5_flush_io (netio_ie5_t * netio_e5_conn);

#endif /* SETUP_NIO_IE5_H */
