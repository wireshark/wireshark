/* ascend.h
 *
 * $Id: ascend.h,v 1.2 1999/09/11 06:49:42 guy Exp $
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@verdict.uthscsa.edu>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

#define ASCEND_MAX_STR_LEN 64
#define ASCEND_MAX_DATA_ROWS 8
#define ASCEND_MAX_DATA_COLS 16
#define ASCEND_MAX_PKT_LEN (ASCEND_MAX_DATA_ROWS * ASCEND_MAX_DATA_COLS)

#define ASCEND_PFX_ETHER 1
#define ASCEND_PFX_PPP_X 2
#define ASCEND_PFX_PPP_R 3

typedef struct {
  guint16 type;                       /* ASCEND_PFX_*, as defined above */
  char    user[ASCEND_MAX_STR_LEN];   /* Username, from header */
  guint32 sess;                       /* Session number */
  guint32 task;                       /* Task number */
  guint32 secs;
  guint32 usecs;
  guint32 caplen;
  guint32 len;
} ascend_pkthdr;

#define ASCEND_PKTHDR_OFFSET sizeof(ascend_pkthdr)

int ascend_open(wtap *wth, int *err);
void init_parse_ascend();
int parse_ascend(FILE *fh, void *pd, int len);
int ascend_seek_read (FILE *fh, int seek_off, guint8 *pd, int len);
