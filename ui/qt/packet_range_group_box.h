/* packet_range_group_box.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_RANGE_GROUP_BOX_H
#define PACKET_RANGE_GROUP_BOX_H

#include <config.h>

#include <glib.h>

#include <ui/packet_range.h>

#include <ui/qt/widgets/syntax_line_edit.h>
#include <QGroupBox>

namespace Ui {
class PacketRangeGroupBox;
}

/**
 * UI element for controlling a range selection. The range provided in
 * "initRange" is not owned by this class but will be modified.
 */
class PacketRangeGroupBox : public QGroupBox
{
    Q_OBJECT

public:
    explicit PacketRangeGroupBox(QWidget *parent = 0);
    ~PacketRangeGroupBox();
    void initRange(packet_range_t *range, QString selRange = QString());
    bool isValid();

signals:
    void validityChanged(bool is_valid);
    void rangeChanged();

private:
    void updateCounts();
    void processButtonToggled(bool checked, packet_range_e process);

    Ui::PacketRangeGroupBox *pr_ui_;
    packet_range_t *range_;
    SyntaxLineEdit::SyntaxState syntax_state_;

private slots:
    void on_rangeLineEdit_textChanged(const QString &range_str);

    void on_allButton_toggled(bool checked);

    void on_selectedButton_toggled(bool checked);

    void on_markedButton_toggled(bool checked);

    void on_ftlMarkedButton_toggled(bool checked);

    void on_rangeButton_toggled(bool checked);

    void on_capturedButton_toggled(bool checked);
    void on_displayedButton_toggled(bool checked);
    void on_ignoredCheckBox_toggled(bool checked);
};

#endif // PACKET_RANGE_GROUP_BOX_H
