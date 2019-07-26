/* ber.c
 *
 * Basic Encoding Rules (BER) file reading
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <errno.h>

#include "wtap-int.h"
#include "file_wrappers.h"
#include <wsutil/buffer.h>
#include "ber.h"


#define BER_CLASS_UNI   0
#define BER_CLASS_APP   1
#define BER_CLASS_CON   2

#define BER_UNI_TAG_SEQ 16      /* SEQUENCE, SEQUENCE OF */
#define BER_UNI_TAG_SET 17      /* SET, SET OF */

wtap_open_return_val ber_open(wtap *wth, int *err, gchar **err_info)
{
#define BER_BYTES_TO_CHECK 8
  guint8 bytes[BER_BYTES_TO_CHECK];
  guint8 ber_id;
  gint8 ber_class;
  gint8 ber_tag;
  gboolean ber_pc;
  guint8 oct, nlb = 0;
  int len = 0;
  gint64 file_size;
  int offset = 0, i;

  if (!wtap_read_bytes(wth->fh, &bytes, BER_BYTES_TO_CHECK, err, err_info)) {
    if (*err != WTAP_ERR_SHORT_READ)
      return WTAP_OPEN_ERROR;
    return WTAP_OPEN_NOT_MINE;
  }

  ber_id = bytes[offset++];

  ber_class = (ber_id>>6) & 0x03;
  ber_pc = (ber_id>>5) & 0x01;
  ber_tag = ber_id & 0x1F;

  /* it must be constructed and either a SET or a SEQUENCE */
  /* or a CONTEXT/APPLICATION less than 32 (arbitrary) */
  if(!(ber_pc &&
       (((ber_class == BER_CLASS_UNI) && ((ber_tag == BER_UNI_TAG_SET) || (ber_tag == BER_UNI_TAG_SEQ))) ||
        (((ber_class == BER_CLASS_CON) || (ber_class == BER_CLASS_APP)) && (ber_tag < 32)))))
    return WTAP_OPEN_NOT_MINE;

  /* now check the length */
  oct = bytes[offset++];

  if(oct != 0x80) {
    /* not indefinite length encoded */

    if(!(oct & 0x80))
      /* length fits into a single byte */
      len = oct;
    else {
      nlb = oct & 0x7F; /* number of length bytes */

      if((nlb > 0) && (nlb <= (BER_BYTES_TO_CHECK - 2))) {
        /* not indefinite length and we have read enough bytes to compute the length */
        i = nlb;
        while(i--) {
          oct = bytes[offset++];
          len = (len<<8) + oct;
        }
      }
    }

    len += (2 + nlb); /* add back Tag and Length bytes */
    file_size = wtap_file_size(wth, err);

    if(len != file_size) {
      return WTAP_OPEN_NOT_MINE; /* not ASN.1 */
    }
  } else {
    /* Indefinite length encoded - assume it is BER */
  }

  /* seek back to the start of the file  */
  if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
    return WTAP_OPEN_ERROR;

  wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_BER;
  wth->file_encap = WTAP_ENCAP_BER;
  wth->snapshot_length = 0;

  wth->subtype_read = wtap_full_file_read;
  wth->subtype_seek_read = wtap_full_file_seek_read;
  wth->file_tsprec = WTAP_TSPREC_SEC;

  return WTAP_OPEN_MINE;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
