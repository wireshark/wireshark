/* endpoint_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "endpoint_dialog.h"

#include <epan/maxmind_db.h>

#include <epan/prefs.h>
#include <epan/to_str.h>

#include "ui/recent.h"

#include "wsutil/filesystem.h"
#include "wsutil/file_util.h"
#include "wsutil/pint.h"
#include "wsutil/str_util.h"
#include <wsutil/utf8_entities.h>

#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/variant_pointer.h>
#include <ui/qt/widgets/wireshark_file_dialog.h>
#include <ui/qt/widgets/traffic_tab.h>
#include <ui/qt/widgets/traffic_types_list.h>
#include "main_application.h"

#include <QCheckBox>
#include <QDesktopServices>
#include <QDialogButtonBox>
#include <QMessageBox>
#include <QPushButton>
#include <QUrl>
#include <QTemporaryFile>
#include <QTreeView>
#include <QSortFilterProxyModel>

typedef enum
{
    ENDP_COLUMN_ADDR,
    ENDP_COLUMN_PORT,
    ENDP_COLUMN_PACKETS,
    ENDP_COLUMN_BYTES,
    ENDP_COLUMN_PKT_AB,
    ENDP_COLUMN_BYTES_AB,
    ENDP_COLUMN_PKT_BA,
    ENDP_COLUMN_BYTES_BA,
    ENDP_NUM_COLUMNS,
    ENDP_COLUMN_GEO_COUNTRY = ENDP_NUM_COLUMNS,
    ENDP_COLUMN_GEO_CITY,
    ENDP_COLUMN_GEO_AS_NUM,
    ENDP_COLUMN_GEO_AS_ORG,
    ENDP_NUM_GEO_COLUMNS
} endpoint_column_type_e;

static const QString table_name_ = QObject::tr("Endpoint");

static ATapDataModel * createModel(int protoId, QString filter)
{
    return new EndpointDataModel(protoId, filter);
}

EndpointDialog::EndpointDialog(QWidget &parent, CaptureFile &cf) :
    TrafficTableDialog(parent, cf, table_name_)
{
    trafficList()->setProtocolInfo(table_name_, &(recent.endpoint_tabs));

    trafficTab()->setProtocolInfo(table_name_, trafficList(), &(recent.endpoint_tabs), &(recent.endpoint_tabs_columns), &createModel);
    trafficTab()->setFilter(cf.displayFilter());

    connect(trafficTab(), &TrafficTab::filterAction, this, &EndpointDialog::filterAction);
    connect(trafficTab()->tabBar(), &QTabBar::currentChanged, this, &EndpointDialog::tabChanged);
    connect(trafficTab(), &TrafficTab::tabDataChanged, this, &EndpointDialog::tabChanged);

#ifdef HAVE_MAXMINDDB
    map_bt_ = buttonBox()->addButton(tr("Map"), QDialogButtonBox::ActionRole);
    map_bt_->setToolTip(tr("Draw IPv4 or IPv6 endpoints on a map."));

    QMenu *map_menu_ = new QMenu(map_bt_);
    QAction *action;
    action = map_menu_->addAction(tr("Open in browser"));
    connect(action, &QAction::triggered, this, &EndpointDialog::openMap);
    action = map_menu_->addAction(tr("Save As…"));
    connect(action, &QAction::triggered, this, &EndpointDialog::saveMap);
    map_bt_->setMenu(map_menu_);
#endif

    updateWidgets();
}

void EndpointDialog::captureFileClosing()
{
    trafficTab()->disableTap();
    displayFilterCheckBox()->setEnabled(false);
    TrafficTableDialog::captureFileClosing();
}

void EndpointDialog::tabChanged(int idx)
{
#ifdef HAVE_MAXMINDDB
    if (idx == trafficTab()->currentIndex())
    {
        bool geoIp = trafficTab()->hasGeoIPData(idx);
        map_bt_->setEnabled(geoIp);
    }
#else
    Q_UNUSED(idx);
#endif


    // By default we'll open the last known opened tab from the Profile
    GList *selected_tab = NULL;

    if (!file_closed_) {
        QVariant proto_id = trafficTab()->currentItemData(ATapDataModel::PROTO_ID);
        if (!proto_id.isNull()) {

            for (GList * endTab = recent.endpoint_tabs; endTab; endTab = endTab->next) {
                int protoId = proto_get_id_by_short_name((const char *)endTab->data);
                if ((protoId > -1) && (protoId==proto_id.toInt())) {
                    selected_tab = endTab;
                }
            }

            // Move the selected tab to the head
            if (selected_tab != nullptr) {
                recent.endpoint_tabs = g_list_remove_link(recent.endpoint_tabs, selected_tab);
                recent.endpoint_tabs = g_list_prepend(recent.endpoint_tabs, selected_tab->data);
            }
        }
    }

    TrafficTableDialog::currentTabChanged();
}

#ifdef HAVE_MAXMINDDB
void EndpointDialog::openMap()
{
    QUrl map_file = trafficTab()->createGeoIPMap(false);
    if (!map_file.isEmpty()) {
        QDesktopServices::openUrl(map_file);
    }
}

void EndpointDialog::saveMap()
{
    QString destination_file =
        WiresharkFileDialog::getSaveFileName(this, tr("Save Endpoints Map"),
                "ipmap.html",
                "HTML files (*.html);;GeoJSON files (*.json)");
    if (destination_file.isEmpty()) {
        return;
    }
    QUrl map_file = trafficTab()->createGeoIPMap(destination_file.endsWith(".json"));
    if (!map_file.isEmpty()) {
        QString source_file = map_file.toLocalFile();
        QFile::remove(destination_file);
        if (!QFile::rename(source_file, destination_file)) {
            QMessageBox::warning(this, tr("Map file error"),
                    tr("Failed to save map file %1.").arg(destination_file));
            QFile::remove(source_file);
        }
    }
}
#endif

void EndpointDialog::on_buttonBox_helpRequested()
{
    mainApp->helpTopicAction(HELP_STATS_ENDPOINTS_DIALOG);
}

void init_endpoint_table(struct register_ct* ct, const char *filter)
{
    mainApp->emitStatCommandSignal("Endpoints", filter, GINT_TO_POINTER(get_conversation_proto_id(ct)));
}
