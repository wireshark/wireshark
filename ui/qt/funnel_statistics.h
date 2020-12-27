/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FUNNELSTATISTICS_H
#define FUNNELSTATISTICS_H

#include <QObject>
#include <QAction>
#include <QSet>

#include <epan/funnel.h>
#include "capture_file.h"
#include <ui/qt/filter_action.h>

struct _funnel_ops_t;
struct progdlg;

/**
 * Signature of function that can be called from a custom packet menu entry
 */
typedef void (* funnel_packet_menu_callback)(gpointer, GPtrArray*);

class FunnelStatistics : public QObject
{
    Q_OBJECT
public:
    explicit FunnelStatistics(QObject *parent, CaptureFile &cf);
    ~FunnelStatistics();
    void retapPackets();
    struct progdlg *progressDialogNew(const gchar *task_title, const gchar *item_title, gboolean terminate_is_stop, gboolean *stop_flag);
    const char *displayFilter();
    void emitSetDisplayFilter(const QString filter);
    void reloadPackets();
    void redissectPackets();
    void reloadLuaPlugins();
    void emitApplyDisplayFilter();
    void emitOpenCaptureFile(QString cf_path, QString filter);
    static const QString &actionName() { return action_name_; }

signals:
    void openCaptureFile(QString cf_path, QString filter);
    void setDisplayFilter(QString filter, FilterAction::Action action, FilterAction::ActionType filterType);

public slots:
    void funnelActionTriggered();
    void displayFilterTextChanged(const QString &filter);

private:
    static const QString action_name_;
    struct _funnel_ops_t *funnel_ops_;
    struct _funnel_ops_id_t *funnel_ops_id_;

    CaptureFile &capture_file_;
    QByteArray display_filter_;
    QString prepared_filter_;
};

class FunnelAction : public QAction
{
    Q_OBJECT
public:
    FunnelAction(QString title, funnel_menu_callback callback, gpointer callback_data, gboolean retap, QObject *parent);
    FunnelAction(QString title, funnel_packet_menu_callback callback, gpointer callback_data, gboolean retap, const char *packet_required_fields, QObject *parent);
    ~FunnelAction();
    funnel_menu_callback callback() const;
    QString title() const;
    void triggerCallback();
    void setPacketCallback(funnel_packet_menu_callback packet_callback);
    void setPacketData(GPtrArray* finfos);
    void addToMenu(QMenu * ctx_menu, QHash<QString, QMenu *> menuTextToMenus);
    void setPacketRequiredFields(const char *required_fields_str);
    const QSet<QString> getPacketRequiredFields();
    bool retap();
    QString getPacketSubmenus();

public slots:
    void triggerPacketCallback();

private:
    QString title_;
    QString packetSubmenu_;
    funnel_menu_callback callback_;
    gpointer callback_data_;
    gboolean retap_;
    funnel_packet_menu_callback packetCallback_;
    GPtrArray* packetData_;
    QSet<QString> packetRequiredFields_;
};

extern "C" {
    void funnel_statistics_reload_menus(void);
    void funnel_statistics_load_packet_menus(void);
    gboolean funnel_statistics_packet_menus_modified(void);
} // extern "C"

#endif // FUNNELSTATISTICS_H
