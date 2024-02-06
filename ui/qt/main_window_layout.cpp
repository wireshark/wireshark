/* main_window_layout.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <ui/qt/main_window.h>
#include <ui/qt/widgets/additional_toolbar.h>

#include "ui/recent.h"

#include "epan/prefs.h"

#include <QSplitter>
#include <QVector>
#include <QList>
#include <QWidget>
#include <QRect>
#include <QAction>
#include <QStackedWidget>
#include <QToolBar>

#include <ui/qt/byte_view_tab.h>
#include <ui/qt/packet_list.h>
#include <ui/qt/packet_diagram.h>
#include <ui/qt/proto_tree.h>
#include <ui/qt/welcome_page.h>

#include <wsutil/ws_assert.h>

void MainWindow::showWelcome()
{
    main_stack_->setCurrentWidget(welcome_page_);
}

void MainWindow::showCapture()
{
    main_stack_->setCurrentWidget(&master_split_);
}

QWidget* MainWindow::getLayoutWidget(layout_pane_content_e type) {
    switch (type) {
        case layout_pane_content_none:
            return &empty_pane_;
        case layout_pane_content_plist:
            return packet_list_;
        case layout_pane_content_pdetails:
            return proto_tree_;
        case layout_pane_content_pbytes:
            return byte_view_tab_;
        case layout_pane_content_pdiagram:
            return packet_diagram_;
        default:
            ws_assert_not_reached();
            return NULL;
    }
}


// A new layout should be applied when it differs from the old layout AND
// at the following times:
// - At startup
// - When the preferences change
// - When the profile changes
void MainWindow::layoutPanes()
{
    QVector<unsigned> new_layout = QVector<unsigned>() << prefs.gui_layout_type
                                                       << prefs.gui_layout_content_1
                                                       << prefs.gui_layout_content_2
                                                       << prefs.gui_layout_content_3
                                                       << recent.packet_list_show
                                                       << recent.tree_view_show
                                                       << recent.byte_view_show
                                                       << recent.packet_diagram_show;

    if (cur_layout_ == new_layout) return;

    QSplitter *parents[3];

    // Reparent all widgets and add them back in the proper order below.
    // This hides each widget as well.
    bool frozen = packet_list_->freeze(); // Clears tree, byte view tabs, and diagram.
    packet_list_->setParent(main_stack_);
    proto_tree_->setParent(main_stack_);
    byte_view_tab_->setParent(main_stack_);
    if (packet_diagram_) {
        packet_diagram_->setParent(main_stack_);
    }
    empty_pane_.setParent(main_stack_);
    extra_split_.setParent(main_stack_);

    // XXX We should try to preserve geometries if we can, e.g. by
    // checking to see if the layout type is the same.
    switch(prefs.gui_layout_type) {
    case(layout_type_2):
    case(layout_type_1):
        extra_split_.setOrientation(Qt::Horizontal);
        /* Fall Through */
    case(layout_type_5):
        master_split_.setOrientation(Qt::Vertical);
        break;

    case(layout_type_4):
    case(layout_type_3):
        extra_split_.setOrientation(Qt::Vertical);
        /* Fall Through */
    case(layout_type_6):
        master_split_.setOrientation(Qt::Horizontal);
        break;

    default:
        ws_assert_not_reached();
    }

    switch(prefs.gui_layout_type) {
    case(layout_type_5):
    case(layout_type_6):
        parents[0] = &master_split_;
        parents[1] = &master_split_;
        parents[2] = &master_split_;
        break;
    case(layout_type_2):
    case(layout_type_4):
        parents[0] = &master_split_;
        parents[1] = &extra_split_;
        parents[2] = &extra_split_;
        break;
    case(layout_type_1):
    case(layout_type_3):
        parents[0] = &extra_split_;
        parents[1] = &extra_split_;
        parents[2] = &master_split_;
        break;
    default:
        ws_assert_not_reached();
    }

    if (parents[0] == &extra_split_) {
        master_split_.addWidget(&extra_split_);
    }

    parents[0]->addWidget(getLayoutWidget(prefs.gui_layout_content_1));

    if (parents[2] == &extra_split_) {
        master_split_.addWidget(&extra_split_);
    }

    parents[1]->addWidget(getLayoutWidget(prefs.gui_layout_content_2));
    parents[2]->addWidget(getLayoutWidget(prefs.gui_layout_content_3));

    if (frozen) {
        // Show the packet list here to prevent pending resize events changing columns
        // when the packet list is set as current widget for the first time.
        packet_list_->show();
    }

    const QList<QWidget *> ms_children = master_split_.findChildren<QWidget *>();

    extra_split_.setVisible(ms_children.contains(&extra_split_));
    packet_list_->setVisible(ms_children.contains(packet_list_) && recent.packet_list_show);
    proto_tree_->setVisible(ms_children.contains(proto_tree_) && recent.tree_view_show);
    byte_view_tab_->setVisible(ms_children.contains(byte_view_tab_) && recent.byte_view_show);
    if (packet_diagram_) {
        packet_diagram_->setVisible(ms_children.contains(packet_diagram_) && recent.packet_diagram_show);
    }

    if (frozen) {
        packet_list_->thaw(true);
    }
    cur_layout_ = new_layout;
}

// The recent layout geometry should be applied after the layout has been
// applied AND at the following times:
// - At startup
// - When the profile changes
void MainWindow::applyRecentPaneGeometry()
{
    if (recent.gui_geometry_main_master_split == nullptr ||
        recent.gui_geometry_main_extra_split == nullptr ||
        !master_split_.restoreState(QByteArray::fromHex(recent.gui_geometry_main_master_split)) ||
        !extra_split_.restoreState(QByteArray::fromHex(recent.gui_geometry_main_extra_split))) {
        // Restoring the splitter states via the savedState didn't work,
        // so let's fall back to the older method.
        //
        // XXX This shrinks slightly each time the application is run. For some
        // reason the master_split_ geometry is two pixels shorter when
        // saveWindowGeometry is invoked.

        // This is also an awful lot of trouble to go through to reuse the GTK+
        // pane settings.

        // Force a geometry recalculation
        QWidget *cur_w = main_stack_->currentWidget();
        showCapture();
        QRect geom = main_stack_->geometry();
        QList<int> master_sizes = master_split_.sizes();
        QList<int> extra_sizes = extra_split_.sizes();
        main_stack_->setCurrentWidget(cur_w);

        int master_last_size = master_split_.orientation() == Qt::Vertical ? geom.height() : geom.width();
        master_last_size -= master_split_.handleWidth() * (master_sizes.length() - 1);

        int extra_last_size = extra_split_.orientation() == Qt::Vertical ? geom.height() : geom.width();
        extra_last_size -= extra_split_.handleWidth();

        if (recent.gui_geometry_main_upper_pane > 0) {
            master_sizes[0] = recent.gui_geometry_main_upper_pane;
            master_last_size -= recent.gui_geometry_main_upper_pane;
        } else {
            master_sizes[0] = master_last_size / master_sizes.length();
            master_last_size -= master_last_size / master_sizes.length();
        }

        if (recent.gui_geometry_main_lower_pane > 0) {
            if (master_sizes.length() > 2) {
                master_sizes[1] = recent.gui_geometry_main_lower_pane;
                master_last_size -= recent.gui_geometry_main_lower_pane;
            } else if (extra_sizes.length() > 0) {
                extra_sizes[0] = recent.gui_geometry_main_lower_pane;
                extra_last_size -= recent.gui_geometry_main_lower_pane;
                extra_sizes.last() = extra_last_size;
            }
        } else {
            if (master_sizes.length() > 2) {
                master_sizes[1] = master_last_size / 2;
                master_last_size -= master_last_size / 2;
            } else if (extra_sizes.length() > 0) {
                extra_sizes[0] = extra_last_size / 2;
                extra_last_size -= extra_last_size / 2;
                extra_sizes.last() = extra_last_size;
            }
        }

        master_sizes.last() = master_last_size;

        master_split_.setSizes(master_sizes);
        extra_split_.setSizes(extra_sizes);
    }
}
