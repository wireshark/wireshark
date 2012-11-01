/* packet_range_group_box.h
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef PACKET_RANGE_GROUP_BOX_H
#define PACKET_RANGE_GROUP_BOX_H

#include "config.h"

#include <glib.h>

#include "packet-range.h"

#include "syntax_line_edit.h"
#include <QGroupBox>

namespace Ui {
class PacketRangeGroupBox;
}

class PacketRangeGroupBox : public QGroupBox
{
    Q_OBJECT
    
public:
    explicit PacketRangeGroupBox(QWidget *parent = 0);
    ~PacketRangeGroupBox();
    void initRange(packet_range_t *range);
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
};

#endif // PACKET_RANGE_GROUP_BOX_H
