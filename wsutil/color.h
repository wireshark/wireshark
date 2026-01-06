/** @file
 *
 * Definitions for colors
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef  __COLOR_H__
#define  __COLOR_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <inttypes.h>

/**
 * @brief RGB color representation with 16-bit precision per channel.
 *
 * Encapsulates a color using three 16-bit components: red, green, and blue.
 *
 * @note Values range from 0 to 65535 per channel.
 */
typedef struct {
    uint16_t red;   /**< Red channel (0–65535) */
    uint16_t green; /**< Green channel (0–65535) */
    uint16_t blue;  /**< Blue channel (0–65535) */
} color_t;

/*
 * Extract the red, green, and blue components of a 24-bit RGB value
 * and convert them from [0,255] to [0,65535]. Colors are 16 bits
 * because that's what GdkColor used.
 * We might want to use a more standard, copy+paste-able color scheme
 * such as #RRGGBB instead.
 */
#define RED_COMPONENT(x)   (uint16_t) (((((x) >> 16) & 0xff) * 65535 / 255))
#define GREEN_COMPONENT(x) (uint16_t) (((((x) >>  8) & 0xff) * 65535 / 255))
#define BLUE_COMPONENT(x)  (uint16_t) ( (((x)        & 0xff) * 65535 / 255))

/**
 * @brief Convert a color_t to 24-bit RGB.
 *
 * Reduces each 16-bit channel in `color_t` to 8 bits by discarding the lower byte,
 * then combines them into a single 24-bit RGB value in the format 0xRRGGBB.
 *
 * @param color Pointer to a `color_t` structure containing 16-bit RGB values.
 * @return      24-bit RGB value (0xRRGGBB).
 */
inline static unsigned int
color_t_to_rgb(const color_t *color) {
    return (((color->red >> 8) << 16)
          | ((color->green >> 8) << 8)
          | (color->blue >> 8));
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
