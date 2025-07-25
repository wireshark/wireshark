/** marker_dialog.cpp
 * Marker of customplot
 * By Hamdi Miladi <hamdi.miladi@technica-engineering.de>
 * Copyright 2025 Hamdi Miladi
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ui/qt/marker_dialog.h"
#include <qboxlayout.h>
#include <qlineedit.h>
#include <qcombobox.h>
#include <qlabel.h>
#include <qpushbutton.h>

MarkerDialog::MarkerDialog(QWidget* parent, bool showToMove, const QVector<Marker*>& markers)
    : QDialog(parent),
    result_(QString())
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    QString title, label;
    QStringList names;
    names << QString();
    for (const Marker* m : markers) {
        if (m->visible() && (showToMove || !m->isPosMarker())) {
            names << m->name();
        }
    }

    label = tr("Choose marker:");
    mainLayout->addWidget(new QLabel(label, this));
    QComboBox* combo = new QComboBox(this);
    combo->addItems(names);
    connect(combo, &QComboBox::currentTextChanged, this, &MarkerDialog::comboItemChanged);
    mainLayout->addWidget(combo);
    if (showToMove) {
        label = tr("Enter new position:");
        mainLayout->addWidget(new QLabel(label, this));
        title = tr("Move marker");
        QLineEdit* posLineEdit = new QLineEdit(this);
        connect(posLineEdit, &QLineEdit::textChanged, this,
            [=] {
                result_ = posLineEdit->text();
            });
        mainLayout->addWidget(posLineEdit);
    }
    else {
        title = tr("Delete marker");
    }

    QPushButton* okButton = new QPushButton(tr("OK"), this);
    connect(okButton, &QPushButton::clicked, this, &MarkerDialog::accept);
    mainLayout->addWidget(okButton);

    setLayout(mainLayout);
    setWindowTitle(title);
}

MarkerDialog::~MarkerDialog() = default;

void MarkerDialog::reject()
{
    result_ = QString();
    selected_marker_ = QString();
    this->close();
    QDialog::reject();
}

void MarkerDialog::comboItemChanged(const QString& text)
{
    selected_marker_ = text;
}

Marker::Marker(const double x, const int index, const bool isPosMarker) :
    index_(index),
    x_coord_(x),
    is_pos_marker_(isPosMarker),
    visible_(!isPosMarker)
{}

QString Marker::toHex(long long value)
{
    QString hex = QString::number(qAbs(value), 16).toLower();
    QString prefix("0x");
    return QString("%1%2%3").arg(value < 0 ? "-" : "")
        .arg(prefix)
        .arg(hex);
}

void Marker::setXCoord(double value) {
    x_coord_ = value;
}
