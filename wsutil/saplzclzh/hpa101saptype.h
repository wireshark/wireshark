/* @(#) saptype.h     20.24   SAP   98/02/12


    ========== licence begin  GPL
    Copyright (c) 2000-2005 SAP AG

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; If not, see <https://www.gnu.org/licenses/>.
    ========== licence end




*/
typedef char SAP_CHAR;
typedef unsigned char SAP_BYTE;        /* Value range: 0 .. UCHAR_MAX */
typedef short SAP_SHORT;       /* Value range: SHRT_MIN .. SHRT_MAX */
typedef unsigned short SAP_USHORT;              /* Value range:     */
typedef int SAP_INT;                        /* Value range:         */
typedef unsigned int SAP_UINT;                   /* Value range:    */


/**********************************************************************/
/* Min/max macros                                                     */
/* To prevent compiler warnings the macros MAX and MIN now have the   */
/* same wording as those in /usr/include/sys/param.h.                 */
/**********************************************************************/
#ifndef MIN
  #define MIN(a,b) (((a)<(b))?(a):(b))
#endif

#ifndef MAX
  #define MAX(a,b) (((a)>(b))?(a):(b))
#endif

#define SAPonNT

#define USE(param) ((param)=(param))
