/* buffer.h
 *
 * $Id: buffer.h,v 1.2 1998/11/12 06:01:19 gram Exp $
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

#define SOME_FUNCTIONS_ARE_DEFINES

typedef struct Buffer {

	char			*data;
	unsigned int	allocated;
	unsigned int	start;
	unsigned int	first_free;

} Buffer;

void buffer_init(Buffer* buffer, unsigned int space);
void buffer_free(Buffer* buffer);
void buffer_assure_space(Buffer* buffer, unsigned int space);
void buffer_append(Buffer* buffer, char *from, unsigned int bytes);
void buffer_remove_start(Buffer* buffer, unsigned int bytes);

#ifdef SOME_FUNCTIONS_ARE_DEFINES
 #define buffer_increase_length(buffer,bytes) (buffer)->first_free += (bytes)
 #define buffer_length(buffer) ((buffer)->first_free - (buffer)->start)
 #define buffer_start_ptr(buffer) ((buffer)->data + (buffer)->start)
 #define buffer_end_ptr(buffer) ((buffer)->data + (buffer)->first_free)
#else
 void buffer_increase_length(Buffer* buffer, unsigned int bytes);
 unsigned int buffer_length(Buffer* buffer);
 char* buffer_start_ptr(Buffer* buffer);
 char* buffer_end_ptr(Buffer* buffer);
#endif
