/* tnef.c
 *
 * Transport-Neutral Encapsulation Format (TNEF) file reading
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "tnef.h"

#include "wtap-int.h"
#include "file_wrappers.h"
#include <wsutil/buffer.h>

static int tnef_file_type_subtype = -1;

void register_tnef(void);

wtap_open_return_val tnef_open(wtap *wth, int *err, char **err_info)
{
  uint32_t magic;

  if (!wtap_read_bytes(wth->fh, &magic, sizeof magic, err, err_info))
    return (*err != WTAP_ERR_SHORT_READ) ? WTAP_OPEN_ERROR : WTAP_OPEN_NOT_MINE;

  if (GUINT32_TO_LE(magic) != TNEF_SIGNATURE)
     /* Not a tnef file */
     return WTAP_OPEN_NOT_MINE;

  /* seek back to the start of the file  */
  if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
    return WTAP_OPEN_ERROR;

  wth->file_type_subtype = tnef_file_type_subtype;
  wth->file_encap = WTAP_ENCAP_TNEF;
  wth->snapshot_length = 0;

  wth->subtype_read = wtap_full_file_read;
  wth->subtype_seek_read = wtap_full_file_seek_read;
  wth->file_tsprec = WTAP_TSPREC_SEC;

  return WTAP_OPEN_MINE;
}

static const struct supported_block_type tnef_blocks_supported[] = {
  /*
   * This is a file format that we dissect, so we provide only one
   * "packet" with the file's contents, and don't support any
   * options.
   */
  { WTAP_BLOCK_PACKET, ONE_BLOCK_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info tnef_info = {
  "Transport-Neutral Encapsulation Format", "tnef", NULL, NULL,
  false, BLOCKS_SUPPORTED(tnef_blocks_supported),
  NULL, NULL, NULL
};

void register_tnef(void)
{
  tnef_file_type_subtype = wtap_register_file_type_subtype(&tnef_info);

  /*
   * Register name for backwards compatibility with the
   * wtap_filetypes table in Lua.
   */
  wtap_register_backwards_compatibility_lua_name("TNEF",
                                                 tnef_file_type_subtype);
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
