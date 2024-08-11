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
 * UI element for selecting compression type from among those supported.
 */
class CompressionGroupBox : public QGroupBox
{
    Q_OBJECT

public:
    explicit CompressionGroupBox(QWidget *parent = 0);
    ~CompressionGroupBox();
    wtap_compression_type compressionType() const;
    void setCompressionType(wtap_compression_type type);

signals:
    void stateChanged();

private:
    QButtonGroup *bg_;
};

#endif // COMPRESSION_GROUP_BOX_H
