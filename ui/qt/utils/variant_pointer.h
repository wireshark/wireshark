/** @file
 *
 * Range routines
 *
 * Roland Knall <rknall@gmail.com>
  *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef UI_QT_VARIANT_POINTER_H_
#define UI_QT_VARIANT_POINTER_H_

#include <QVariant>

/**
 * @brief A template utility class for converting between pointers and QVariant objects.
 */
template <typename T> class VariantPointer
{

public:
    /**
     * @brief Converts a QVariant containing a void pointer back to a typed pointer.
     * @param v The QVariant containing the pointer data.
     * @return A pointer of type T.
     */
    static T* asPtr(QVariant v)
    {
        return  (T *) v.value<void *>();
    }

    /**
     * @brief Converts a typed pointer into a QVariant.
     * @param ptr The pointer to convert.
     * @return A QVariant encapsulating the pointer.
     */
    static QVariant asQVariant(T* ptr)
    {
        return QVariant::fromValue((void *) ptr);
    }
};

#endif /* UI_QT_VARIANT_POINTER_H_ */
