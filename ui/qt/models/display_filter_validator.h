/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DISPLAY_FILTER_VALIDATOR_H
#define DISPLAY_FILTER_VALIDATOR_H

#include <ui/qt/models/filter_validator.h>

/**
 * @brief FilterValidator for Wireshark display filters.
 *
 * validate() compiles the expression with dfilter_compile_full() and maps the
 * result to the FilterEdit syntax states:
 *  - empty            -> Acceptable (host shows Empty, no tint)
 *  - compiles cleanly -> Acceptable (Valid)
 *  - compiles with a warning or a deprecated token -> Acceptable with a
 *    non-empty Detail::deprecatedToken (host shows Deprecated/amber)
 *  - fails with DF_ERROR_UNEXPECTED_END -> Intermediate (still typing; never red)
 *  - fails otherwise  -> Invalid, with the error message and location stashed in
 *    Detail so the host can render lastErrorFull().
 *
 * Synchronous, like the capture validator: it runs on the host widget's
 * debounce and reads lastDetail() immediately afterwards.
 */
class DisplayFilterValidator : public FilterValidator
{
    Q_OBJECT

public:
    explicit DisplayFilterValidator(QObject *parent = nullptr);

    QValidator::State validate(QString &input, int &pos) const override;
    Detail lastDetail() const override { return detail_; }

private:
    mutable Detail detail_; /**< Stash for the most recent validate(); single-owner. */
};

#endif // DISPLAY_FILTER_VALIDATOR_H
