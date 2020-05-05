/* packet_diagram.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_DIAGRAM_H
#define PACKET_DIAGRAM_H

#include <config.h>

#include <epan/proto.h>

#include "cfile.h"

#include <ui/qt/utils/field_information.h>

#include <QGraphicsView>

class DiagramLayout;

class PacketDiagram : public QGraphicsView
{
    Q_OBJECT
public:
    PacketDiagram(QWidget *parent = nullptr);
    ~PacketDiagram();
    void setRootNode(proto_node *root_node);
    void clear();

signals:
    void fieldSelected(FieldInformation *);

public slots:
    void setCaptureFile(capture_file *cf);
    void setFont(const QFont &font);
    void selectedFieldChanged(FieldInformation *finfo);
    void selectedFrameChanged(QList<int> frames);

protected:
    virtual void contextMenuEvent(QContextMenuEvent *event) override;

private slots:
    void connectToMainWindow();
    void sceneSelectionChanged();

private:
    void addDiagram(proto_node *tl_node);
    void setSelectedField(field_info *fi);
    QImage exportToImage();
#if defined(QT_SVG_LIB) && 0
    QByteArray exportToSvg();
#endif

    void showFieldsToggled(bool checked);
    void saveAsTriggered();
    void copyAsRasterTriggered();
#if defined(QT_SVG_LIB) && !defined(Q_OS_MAC) && 0
    void copyAsSvgTriggered();
#endif

    DiagramLayout *layout_;
    capture_file *cap_file_;
    proto_node *root_node_;
    field_info *selected_field_;
    int y_pos_;
};

#endif // PACKET_DIAGRAM_H
