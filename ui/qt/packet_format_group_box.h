/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef PACKET_FORMAT_GROUP_BOX_H
#define PACKET_FORMAT_GROUP_BOX_H

#include "file.h"

#include <QGroupBox>

class PacketFormatGroupBox : public QGroupBox
{
    Q_OBJECT

public:
    explicit PacketFormatGroupBox(QWidget *parent = 0);

    virtual bool isValid() const;
    virtual void updatePrintArgs(print_args_t& print_args) = 0;

signals:
    void formatChanged();

};

class PacketFormatBlankGroupBox : public PacketFormatGroupBox
{
    Q_OBJECT

public:
    explicit PacketFormatBlankGroupBox(QWidget *parent = 0);

    void updatePrintArgs(print_args_t& print_args) override;
};

namespace Ui {
class PacketFormatTextGroupBox;
}

class PacketFormatTextGroupBox : public PacketFormatGroupBox
{
    Q_OBJECT

public:
    explicit PacketFormatTextGroupBox(QWidget *parent = 0);
    ~PacketFormatTextGroupBox();

    bool isValid() const override;
    void updatePrintArgs(print_args_t& print_args) override;

    bool summaryEnabled() const;
    bool detailsEnabled() const;
    bool bytesEnabled() const;

    bool includeColumnHeadingsEnabled() const;

    bool allCollapsedEnabled() const;
    bool asDisplayedEnabled() const;
    bool allExpandedEnabled() const;

    uint getHexdumpOptions() const;

private slots:
    void on_summaryCheckBox_toggled(bool checked);
    void on_detailsCheckBox_toggled(bool checked);
    void on_bytesCheckBox_toggled(bool checked);

    void on_includeColumnHeadingsCheckBox_toggled(bool checked);

    void on_allCollapsedButton_toggled(bool checked);
    void on_asDisplayedButton_toggled(bool checked);
    void on_allExpandedButton_toggled(bool checked);

    void on_includeDataSourcesCheckBox_toggled(bool checked);
    void on_timestampCheckBox_toggled(bool checked);

private:
    Ui::PacketFormatTextGroupBox *pf_ui_;
};

namespace Ui {
class PacketFormatJSONGroupBox;
}

class PacketFormatJSONGroupBox : public PacketFormatGroupBox
{
    Q_OBJECT

public:
    explicit PacketFormatJSONGroupBox(QWidget *parent = 0);
    ~PacketFormatJSONGroupBox();

    void updatePrintArgs(print_args_t& print_args) override;
    bool noDuplicateKeys();

private:
    Ui::PacketFormatJSONGroupBox *pf_ui_;
};

#endif // PACKET_FORMAT_GROUP_BOX_H
