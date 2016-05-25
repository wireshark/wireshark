/* sequence_diagram.h
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

#ifndef SEQUENCE_DIAGRAM_H
#define SEQUENCE_DIAGRAM_H

#include <config.h>

#include <glib.h>

#include <epan/address.h>

#include <QObject>
#include <QMultiMap>
#include "qcustomplot.h"

struct _seq_analysis_info;
struct _seq_analysis_item;

// Some of this is probably unnecessary
class WSCPSeqData
{
public:
  WSCPSeqData();
  WSCPSeqData(double key, _seq_analysis_item *value);
  double key;
  struct _seq_analysis_item *value;
};

typedef QMap<double, WSCPSeqData> WSCPSeqDataMap;

class SequenceDiagram : public QCPAbstractPlottable
{
    Q_OBJECT
public:
    explicit SequenceDiagram(QCPAxis *keyAxis, QCPAxis *valueAxis, QCPAxis *commentAxis);
    virtual ~SequenceDiagram();

    // getters:
    // Next / previous packet.
    int adjacentPacket(bool next);

    double selectedKey() { return selected_key_; }

    // setters:
    void setData(struct _seq_analysis_info *sainfo);

    // non-property methods:
    struct _seq_analysis_item *itemForPosY(int ypos);

    // reimplemented virtual methods:
    virtual void clearData() { data_->clear(); }
    virtual double selectTest(const QPointF &pos, bool onlySelectable, QVariant *details=0) const;

public slots:
    void setSelectedPacket(int selected_packet);

protected:
    virtual void draw(QCPPainter *painter);
    virtual void drawLegendIcon(QCPPainter *painter, const QRectF &rect) const;
    virtual QCPRange getKeyRange(bool &validRange, SignDomain inSignDomain=sdBoth) const;
    virtual QCPRange getValueRange(bool &validRange, SignDomain inSignDomain=sdBoth) const;

private:
    QCPAxis *key_axis_;
    QCPAxis *value_axis_;
    QCPAxis *comment_axis_;
    WSCPSeqDataMap *data_;
    struct _seq_analysis_info *sainfo_;
    guint32 selected_packet_;
    double selected_key_;
};

#endif // SEQUENCE_DIAGRAM_H

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
