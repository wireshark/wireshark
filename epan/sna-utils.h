/* sna-utils.h
 * Definitions for SNA dissection.
 *
 * $Id: sna-utils.h,v 1.2 2001/04/01 07:06:24 hagbard Exp $
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
 */

#ifndef __SNA_UTILS__
#define __SNA_UTILS__

#include <glib.h>
#include <stdio.h>

/*
 * Structure used to represent an FID Type 4 address; gives the layout of the
 * data pointed to by an AT_SNA "address" structure if the size is
 * SNA_FID_TYPE_4_ADDR_LEN.
 */
#define	SNA_FID_TYPE_4_ADDR_LEN	6
struct sna_fid_type_4_addr {
	guint32	saf;
	guint16	ef;
};

/*
 * Routine to take an SNA FID Type 4 address and generate a string.
 */
extern gchar *sna_fid_type_4_addr_to_str(const struct sna_fid_type_4_addr *addrp);

#endif
