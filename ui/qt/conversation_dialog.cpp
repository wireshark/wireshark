/* conversation_dialog.cpp
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

#include "conversation_dialog.h"
#include "ui_conversation_dialog.h"

#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/stat_cmd_args.h>

#include <epan/dissectors/packet-tcp.h>

#include "ui/recent.h"
#include "ui/tap-tcp-stream.h"

#include "wireshark_application.h"

#include <QByteArray>
#include <QCheckBox>
#include <QClipboard>
#include <QContextMenuEvent>
#include <QList>
#include <QMap>
#include <QMessageBox>
#include <QTabWidget>
#include <QTextStream>
#include <QToolButton>

// To do:
// - https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6727
//   - Wide last column?
//   + No arrows on unsorted columns
//   - Add follow stream to context menu
//   + Change "A <- B" to "B -> A"
// - Improper wildcard handling https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8010
// - TShark consolidation https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6310
// - Display filter entry?
// - Add follow, copy & graph actions to context menu.

// Bugs:
// - Name resolution doesn't do anything if its preference is disabled.
// - Columns don't resize correctly.
// - Closing the capture file clears conversation data.

// Fixed bugs:
// - Friendly unit displays https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=9231
// - Misleading bps calculation https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8703

ConversationDialog::ConversationDialog(QWidget *parent, capture_file *cf, int proto_id, const char *filter) :
    QDialog(parent),
    ui(new Ui::ConversationDialog),
    cap_file_(cf),
    filter_(filter)
{
    ui->setupUi(this);
    setAttribute(Qt::WA_DeleteOnClose, true);

    // XXX Use recent settings instead
    if (parent) {
        resize(parent->width(), parent->height() * 3 / 4);
    }

    QMenu *copy_menu = new QMenu();
    QAction *ca;
    copy_bt_ = ui->buttonBox->addButton(tr("Copy"), QDialogButtonBox::ActionRole);
    ca = copy_menu->addAction(tr("as CSV"));
    ca->setToolTip(tr("Copy all values of this page to the clipboard in CSV (Comma Separated Values) format."));
    connect(ca, SIGNAL(triggered()), this, SLOT(copyAsCsv()));
    ca = copy_menu->addAction(tr("as YAML"));
    ca->setToolTip(tr("Copy all values of this page to the clipboard in the YAML data serialization format."));
    connect(ca, SIGNAL(triggered()), this, SLOT(copyAsYaml()));
    copy_bt_->setMenu(copy_menu);

    follow_bt_ = ui->buttonBox->addButton(tr("Follow Stream..."), QDialogButtonBox::ActionRole);
    follow_bt_->setToolTip(tr("Follow a TCP or UDP stream."));
    connect(follow_bt_, SIGNAL(clicked()), this, SLOT(followStream()));

    graph_bt_ = ui->buttonBox->addButton(tr("Graph..."), QDialogButtonBox::ActionRole);
    graph_bt_->setToolTip(tr("Graph a TCP conversation."));
    connect(graph_bt_, SIGNAL(clicked()), this, SLOT(graphTcp()));

    QList<int> conv_protos;
    for (GList *conv_tab = recent.conversation_tabs; conv_tab; conv_tab = conv_tab->next) {
        int proto_id = proto_get_id_by_short_name((const char *)conv_tab->data);
        if (proto_id > -1 && !conv_protos.contains(proto_id)) {
            conv_protos.append(proto_id);
        }
    }

    // Reasonable defaults?
    if (conv_protos.isEmpty()) {
        conv_protos << proto_get_id_by_filter_name( "tcp" ) << proto_get_id_by_filter_name( "eth" )
                    << proto_get_id_by_filter_name( "ip" ) << proto_get_id_by_filter_name( "ipv6" )
                    << proto_get_id_by_filter_name( "udp" );
    }

    // Bring the command-line specified type to the front.
    if (get_conversation_by_proto_id(proto_id)) {
        conv_protos.removeAll(proto_id);
        conv_protos.prepend(proto_id);
    }

    // QTabWidget selects the first item by default.
    foreach (int conv_proto, conv_protos) {
        addConversationTable(get_conversation_by_proto_id(conv_proto));
    }

    for (guint i = 0; i < conversation_table_get_num(); i++) {
        int proto_id = get_conversation_proto_id(get_conversation_table_by_num(i));
        if (proto_id < 0) {
            continue;
        }
        QString title = proto_get_protocol_short_name(find_protocol_by_id(proto_id));

        QAction *conv_action = new QAction(title, this);
        conv_action->setData(qVariantFromValue(proto_id));
        conv_action->setCheckable(true);
        conv_action->setChecked(conv_protos.contains(proto_id));
        connect(conv_action, SIGNAL(triggered()), this, SLOT(toggleConversation()));
        conv_type_menu_.addAction(conv_action);
    }

    ui->conversationTypePushButton->setMenu(&conv_type_menu_);

    updateWidgets();
    itemSelectionChanged();

    ui->nameResolutionCheckBox->setChecked(gbl_resolv_flags.network_name);

    ui->conversationTabWidget->currentWidget()->setFocus();

    connect(ui->conversationTabWidget, SIGNAL(currentChanged(int)),
            this, SLOT(itemSelectionChanged()));

    if (cap_file_) {
        cf_retap_packets(cap_file_);
    }
}

ConversationDialog::~ConversationDialog()
{
    prefs_clear_string_list(recent.conversation_tabs);
    recent.conversation_tabs = NULL;

    ConversationTreeWidget *cur_tree = qobject_cast<ConversationTreeWidget *>(ui->conversationTabWidget->currentWidget());
    foreach (QAction *ca, conv_type_menu_.actions()) {
        int proto_id = ca->data().value<int>();
        if (proto_id_to_tree_.contains(proto_id) && ca->isChecked()) {
            char *title = g_strdup(proto_get_protocol_short_name(find_protocol_by_id(proto_id)));
            if (proto_id_to_tree_[proto_id] == cur_tree) {
                recent.conversation_tabs = g_list_prepend(recent.conversation_tabs, title);
            } else {
                recent.conversation_tabs = g_list_append(recent.conversation_tabs, title);
            }
        }
    }
    delete ui;
}

void ConversationDialog::setCaptureFile(capture_file *cf)
{
    if (!cf) { // We only want to know when the file closes.
        cap_file_ = NULL;
        ui->displayFilterCheckBox->setEnabled(false);
    }
}

bool ConversationDialog::addConversationTable(register_ct_t* table)
{
    int proto_id = get_conversation_proto_id(table);

    if (!table || proto_id_to_tree_.contains(proto_id)) {
        return false;
    }

    ConversationTreeWidget *conv_tree = new ConversationTreeWidget(this, table);

    proto_id_to_tree_[proto_id] = conv_tree;
    const char* table_name = proto_get_protocol_short_name(find_protocol_by_id(proto_id));

    ui->conversationTabWidget->addTab(conv_tree, table_name);

    connect(conv_tree, SIGNAL(itemSelectionChanged()),
            this, SLOT(itemSelectionChanged()));
    connect(conv_tree, SIGNAL(titleChanged(QWidget*,QString)),
            this, SLOT(setTabText(QWidget*,QString)));
    connect(conv_tree, SIGNAL(filterAction(QString&,FilterAction::Action,FilterAction::ActionType)),
            this, SLOT(chainFilterAction(QString&,FilterAction::Action,FilterAction::ActionType)));
    connect(ui->nameResolutionCheckBox, SIGNAL(toggled(bool)),
            conv_tree, SLOT(setNameResolutionEnabled(bool)));

    // XXX Move to ConversationTreeWidget ctor?
    const char *filter = NULL;
    if (ui->displayFilterCheckBox->isChecked()) {
        filter = cap_file_->dfilter;
    } else if (!filter_.isEmpty()) {
        filter = filter_.toUtf8().constData();
    }

    conv_tree->conversationHash()->user_data = conv_tree;

    GString *error_string = register_tap_listener(proto_get_protocol_filter_name(proto_id), conv_tree->conversationHash(), filter, 0,
                                                  ConversationTreeWidget::tapReset,
                                                  get_conversation_packet_func(table),
                                                  ConversationTreeWidget::tapDraw);

    if (error_string) {
        QMessageBox::warning(this, tr("Conversation %1 failed to register tap listener").arg(table_name),
                             error_string->str);
        g_string_free(error_string, TRUE);
    }

    return true;
}

conv_item_t *ConversationDialog::currentConversation()
{
    ConversationTreeWidget *cur_tree = qobject_cast<ConversationTreeWidget *>(ui->conversationTabWidget->currentWidget());

    if (!cur_tree || cur_tree->selectedItems().count() < 1) {
        return NULL;
    }

    return cur_tree->selectedItems()[0]->data(0, Qt::UserRole).value<conv_item_t *>();
}

void ConversationDialog::followStream()
{
    conv_item_t *conv_item = currentConversation();
    if (!conv_item) {
        return;
    }

    QString filter;
    follow_type_t ftype = FOLLOW_TCP;
    switch (conv_item->ptype) {
    case PT_TCP:
        filter = QString("tcp.stream eq %1").arg(conv_item->conv_id);
        break;
    case PT_UDP:
        filter = QString("udp.stream eq %1").arg(conv_item->conv_id);
        ftype = FOLLOW_UDP;
        break;
    default:
        break;
    }

    if (filter.length() < 1) {
        return;
    }

    chainFilterAction(filter, FilterAction::ActionApply, FilterAction::ActionTypePlain);
    openFollowStreamDialog(ftype);
}

void ConversationDialog::copyAsCsv()
{
    ConversationTreeWidget *cur_tree = qobject_cast<ConversationTreeWidget *>(ui->conversationTabWidget->currentWidget());
    if (!cur_tree) {
        return;
    }

    QString csv;
    QTextStream stream(&csv, QIODevice::Text);
    for (int row = -1; row < cur_tree->topLevelItemCount(); row ++) {
        QStringList rdsl;
        foreach (QVariant v, cur_tree->rowData(row)) {
            if (!v.isValid()) {
                rdsl << "\"\"";
            } else if ((int) v.type() == (int) QMetaType::QString) {
                rdsl << QString("\"%1\"").arg(v.toString());
            } else {
                rdsl << v.toString();
            }
        }
        stream << rdsl.join(",") << endl;
    }
    wsApp->clipboard()->setText(stream.readAll());
}

void ConversationDialog::copyAsYaml()
{
    ConversationTreeWidget *cur_tree = qobject_cast<ConversationTreeWidget *>(ui->conversationTabWidget->currentWidget());
    if (!cur_tree) {
        return;
    }

    QString yaml;
    QTextStream stream(&yaml, QIODevice::Text);
    stream << "---" << endl;
    for (int row = -1; row < cur_tree->topLevelItemCount(); row ++) {
        stream << "-" << endl;
        foreach (QVariant v, cur_tree->rowData(row)) {
            stream << " - " << v.toString() << endl;
        }
    }
    wsApp->clipboard()->setText(stream.readAll());
}

void ConversationDialog::graphTcp()
{
    conv_item_t *conv_item = currentConversation();
    if (!conv_item) {
        return;
    }

    // XXX The GTK+ code opens the TCP Stream dialog. We might want
    // to open the IO Graph dialog instead.
    QString filter;
    if (conv_item->ptype == PT_TCP) {
        filter = QString("tcp.stream eq %1").arg(conv_item->conv_id);
    } else {
        return;
    }

    chainFilterAction(filter, FilterAction::ActionApply, FilterAction::ActionTypePlain);
    openTcpStreamGraph(GRAPH_TSEQ_TCPTRACE);
}

void ConversationDialog::updateWidgets()
{
    QWidget *cur_w = ui->conversationTabWidget->currentWidget();
    ui->conversationTabWidget->setUpdatesEnabled(false);
    ui->conversationTabWidget->clear();
    foreach (QAction *ca, conv_type_menu_.actions()) {
        int proto_id = ca->data().value<int>();
        if (proto_id_to_tree_.contains(proto_id) && ca->isChecked()) {
            ui->conversationTabWidget->addTab(proto_id_to_tree_[proto_id],
                                              proto_id_to_tree_[proto_id]->conversationTitle());
            proto_id_to_tree_[proto_id]->setNameResolutionEnabled(ui->nameResolutionCheckBox->isChecked());
        }
    }
    ui->conversationTabWidget->setCurrentWidget(cur_w);
    ui->conversationTabWidget->setUpdatesEnabled(true);
}

void ConversationDialog::toggleConversation()
{
    QAction *ca = qobject_cast<QAction *>(QObject::sender());
    if (!ca) {
        return;
    }

    int proto_id = ca->data().value<int>();
    register_ct_t* table = get_conversation_by_proto_id(proto_id);

    bool new_conv = addConversationTable(table);
    updateWidgets();

    if (ca->isChecked()) {
        ui->conversationTabWidget->setCurrentWidget(proto_id_to_tree_[proto_id]);
    }

    if (new_conv) {
        if (cap_file_) {
            cf_retap_packets(cap_file_);
        }
    }
}

void ConversationDialog::itemSelectionChanged()
{
    bool copy_enable = ui->conversationTabWidget->currentWidget() ? true : false;
    bool follow_enable = false, graph_enable = false;
    conv_item_t *conv_item = currentConversation();

    if (cap_file_ && conv_item) {
        switch (conv_item->ptype) {
        case PT_TCP:
            graph_enable = true;
            // Fall through
        case PT_UDP:
            follow_enable = true;
            break;
        default:
            break;
        }
    }

    copy_bt_->setEnabled(copy_enable);
    follow_bt_->setEnabled(follow_enable);
    graph_bt_->setEnabled(graph_enable);
}

void ConversationDialog::on_nameResolutionCheckBox_toggled(bool checked)
{
    Q_UNUSED(checked);
    updateWidgets();
}

void ConversationDialog::on_displayFilterCheckBox_toggled(bool checked)
{
    if (!cap_file_) {
        return;
    }

    const char *filter = NULL;
    if (checked) {
        filter = cap_file_->dfilter;
    } else if (!filter_.isEmpty()) {
        filter = filter_.toUtf8().constData();
    }

    for (int i = 0; i < ui->conversationTabWidget->count(); i++) {
        set_tap_dfilter(ui->conversationTabWidget->widget(i), filter);
    }

    cf_retap_packets(cap_file_);
}

void ConversationDialog::setTabText(QWidget *tree, const QString &text)
{
    // Could use QObject::sender as well
    int index = ui->conversationTabWidget->indexOf(tree);
    if (index >= 0) {
        ui->conversationTabWidget->setTabText(index, text);
    }
}

void ConversationDialog::chainFilterAction(QString &filter, FilterAction::Action action, FilterAction::ActionType type)
{
    if (cap_file_) { // We probably shouldn't fail silently
        emit filterAction(filter, action, type);
    }
}

void ConversationDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_STATS_CONVERSATIONS_DIALOG);
}

void init_conversation_table(struct register_ct* ct, const char *filter)
{
    Q_UNUSED(ct)
    wsApp->emitStatCommandSignal("Conversation", filter, GINT_TO_POINTER(get_conversation_proto_id(ct)));
}

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
