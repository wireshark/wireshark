/* @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "compression_group_box.h"

#include <QRadioButton>
#include <QButtonGroup>
#include <QVBoxLayout>

CompressionGroupBox::CompressionGroupBox(QWidget *parent) :
    QGroupBox(parent)
{
    setTitle(tr("Compression options"));
    setFlat(true);


    bg_ = new QButtonGroup(this);
    QVBoxLayout *vbox = new QVBoxLayout();

    QRadioButton *radio1 = new QRadioButton(tr("&Uncompressed"));
    bg_->addButton(radio1, WTAP_UNCOMPRESSED);
    vbox->addWidget(radio1);

#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
    QRadioButton *radio2 = new QRadioButton(tr("Compress with g&zip"));
    bg_->addButton(radio2, WTAP_GZIP_COMPRESSED);
    vbox->addWidget(radio2);
#endif
#ifdef HAVE_LZ4FRAME_H
    QRadioButton *radio3 = new QRadioButton(tr("Compress with &LZ4"));
    bg_->addButton(radio3, WTAP_LZ4_COMPRESSED);
    vbox->addWidget(radio3);
#endif

    radio1->setChecked(true);

    setLayout(vbox);

    connect(bg_, &QButtonGroup::idToggled, [=] { emit stateChanged(); });
}

CompressionGroupBox::~CompressionGroupBox()
{
}

wtap_compression_type CompressionGroupBox::compressionType() const
{
    return static_cast<wtap_compression_type>(bg_->checkedId());
}

void CompressionGroupBox::setCompressionType(wtap_compression_type type)
{
    QAbstractButton *button = bg_->button(type);
    if (button != nullptr) {
        button->setChecked(true);
    }
}

