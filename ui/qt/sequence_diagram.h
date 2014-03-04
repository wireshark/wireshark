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

#include "config.h"

#include <glib.h>

#include <epan/address.h>

#include "ui/tap-sequence-analysis.h"

#include <QObject>
#include <QMultiMap>
#include "qcustomplot.h"

// Most of this is probably unnecessary
class WSCPSeqData
{
public:
  WSCPSeqData();
  WSCPSeqData(double key, seq_analysis_item_t *value);
  double key;
  seq_analysis_item_t *value;
};
Q_DECLARE_TYPEINFO(WSCPSeqData, Q_MOVABLE_TYPE);

typedef QMap<double, WSCPSeqData> WSCPSeqDataMap;
typedef QMapIterator<double, WSCPSeqData> WSCPSeqDataMapIterator;
typedef QMutableMapIterator<double, WSCPSeqData> WSCPSeqDataMutableMapIterator;

class SequenceDiagram : public QCPAbstractPlottable
{
    Q_OBJECT
public:
    explicit SequenceDiagram(QCPAxis *keyAxis, QCPAxis *valueAxis, QCPAxis *commentAxis);

    // getters:

    // setters:
    void setData(seq_analysis_info_t *sainfo);

    // non-property methods:
    seq_analysis_item_t *itemForPosY(int ypos);

    // reimplemented virtual methods:
    virtual void clearData() {}
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
    seq_analysis_info_t *sainfo_;
    guint32 selected_packet_;
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
