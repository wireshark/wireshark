#ifndef __CRC11_____H__

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif
/**
 * Functions and types for CRC checks.
 *
 * Generated on Tue Aug  7 15:45:57 2012,
 * by pycrc v0.7.10, http://www.tty1.net/pycrc/
 * using the configuration:
 *    Width        = 11
 *    Poly         = 0x307
 *    XorIn        = 0x000
 *    ReflectIn    = False
 *    XorOut       = 0x000
 *    ReflectOut   = False
 *    Algorithm    = table-driven
 *****************************************************************************/
guint16 crc11_307_noreflect_noxor(const guint8 *data, guint64 data_len);

#ifdef __cplusplus
}           /* closing brace for extern "C" */
#endif

#endif /*__CRC11_____H__*/
