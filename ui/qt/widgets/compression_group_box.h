/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef COMPRESSION_GROUP_BOX_H
#define COMPRESSION_GROUP_BOX_H

#include <config.h>

#include <QGroupBox>

#include <wiretap/wtap.h>

class QButtonGroup;

/**
 * @brief UI element for selecting compression type from among those supported.
 */
class CompressionGroupBox : public QGroupBox
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new CompressionGroupBox.
     * @param parent The parent widget, defaults to 0.
     */
    explicit CompressionGroupBox(QWidget *parent = 0);

    /**
     * @brief Destroys the CompressionGroupBox.
     */
    ~CompressionGroupBox();

    /**
     * @brief Retrieves the currently selected compression type.
     * @return The selected compression type.
     */
    ws_compression_type compressionType() const;

    /**
     * @brief Sets the compression type for the group box.
     * @param type The compression type to set.
     */
    void setCompressionType(ws_compression_type type);

signals:
    /**
     * @brief Signal emitted when the compression state or selection changes.
     */
    void stateChanged();

private:
    /** Pointer to the button group managing the compression choices. */
    QButtonGroup *bg_;
};

#endif // COMPRESSION_GROUP_BOX_H
