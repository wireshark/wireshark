/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QAbstractScrollArea>

struct tvbuff;

class BaseDataSourceView : public QAbstractScrollArea
{
    Q_OBJECT
public:
    explicit BaseDataSourceView(const QByteArray &data, QWidget *parent = nullptr) :
        QAbstractScrollArea(parent),
        data_(data),
        tvb_(nullptr),
        tab_index_(0)
    {}

    virtual QSize minimumSizeHint() const { return QSize(); }

    virtual bool isEmpty() const { return data_.isEmpty(); }

    struct tvbuff *tvb() const { return tvb_; }
    void setTvb(struct tvbuff *tvb) { tvb_ = tvb; }

    int tabIndex() const { return tab_index_; }
    void setTabIndex(int tab_index) { tab_index_ = tab_index; }

signals:
    void byteHovered(int pos);
    void byteSelected(int pos);

public slots:
    virtual void setMonospaceFont(const QFont &mono_font) = 0;
    virtual void detachData() { data_.detach(); }

    virtual void markProtocol(int start, int length) = 0;
    virtual void markField(int start, int length, bool scroll_to = true) = 0;
    virtual void markAppendix(int start, int length) = 0;
    virtual void unmarkField() = 0;
    virtual void saveSelected(int start) = 0;

protected:
    QByteArray data_;

private:
    struct tvbuff *tvb_;
    int tab_index_;
};
