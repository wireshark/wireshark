/** @file
 *
 * GSoC 2013 - QtShark
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef STRATOSHARK_CAPTURE_FILE_PROPERTIES_DIALOG_H
#define STRATOSHARK_CAPTURE_FILE_PROPERTIES_DIALOG_H

#include "capture_file_properties_dialog.h"

namespace Ui {
class StratosharkCaptureFilePropertiesDialog;
}

/**
 * @brief Stratoshark-specific capture file properties dialog, overriding
 *        the base CaptureFilePropertiesDialog string accessors to substitute
 *        Stratoshark terminology (e.g. "event" in place of "packet").
 */
class StratosharkCaptureFilePropertiesDialog : public CaptureFilePropertiesDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the Stratoshark capture file properties dialog.
     * @param parent       Parent widget reference.
     * @param capture_file Capture file whose properties are to be displayed.
     */
    explicit StratosharkCaptureFilePropertiesDialog(QWidget &parent, CaptureFile &capture_file);

    /**
     * @brief Destroys the dialog.
     */
    virtual ~StratosharkCaptureFilePropertiesDialog();

protected:
    /** @return Localised string for the introductory section header. */
    virtual QString getStartTextString() const override;

    /** @return Localised label for the first item (e.g. "First event"). */
    virtual QString getFirstItemString() const override;

    /** @return Localised label for the last item (e.g. "Last event"). */
    virtual QString getLastItemString() const override;

    /** @return Localised string for the closing section footer. */
    virtual QString getEndTextString() const override;

    /** @return Localised label for the dropped-item count statistic. */
    virtual QString getDroppedItemString() const override;

    /** @return Localised label for the item size limit statistic. */
    virtual QString getItemSizeLimitString() const override;

    /** @return Localised column or row title used in the statistics table. */
    virtual QString getRowTitleString() const override;

    /** @return Localised label for the average item size statistic. */
    virtual QString getAvgItemSizeString() const override;

    /** @return Localised label for the item comment field. */
    virtual QString getItemCommentString() const override;

    /** @return Localised label for the "Created by" metadata field. */
    virtual QString getCreatedByString() const override;
};

#endif
