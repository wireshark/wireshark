#ifndef _CRCDRM_H

#include <stdlib.h>

unsigned long crc_drm(const char *data, size_t bytesize,
	unsigned short num_crc_bits, unsigned long crc_gen, int invert);
#endif
