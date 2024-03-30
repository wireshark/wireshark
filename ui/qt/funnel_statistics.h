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
#include <QPointer>

#include <epan/funnel.h>
#include "io_console_dialog.h"
#include "capture_file.h"
#include <ui/qt/filter_action.h>

struct _funnel_ops_t;
struct progdlg;

/**
 * Signature of function that can be called from a custom packet menu entry
 */
typedef void (* funnel_packet_menu_callback)(void *, GPtrArray*);

class FunnelStatistics : public QObject
{
    Q_OBJECT
public:
    explicit FunnelStatistics(QObject *parent, CaptureFile &cf);
    ~FunnelStatistics();
    void retapPackets();
    struct progdlg *progressDialogNew(const char *task_title, const char *item_title, bool terminate_is_stop, bool *stop_flag);
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
    FunnelAction(QObject *parent = nullptr);
    FunnelAction(QString title, funnel_menu_callback callback, void *callback_data, bool retap, QObject *parent);
    FunnelAction(QString title, funnel_packet_menu_callback callback, void *callback_data, bool retap, const char *packet_required_fields, QObject *parent);
    ~FunnelAction();
    funnel_menu_callback callback() const;
    QString title() const;
    virtual void triggerCallback();
    void setPacketCallback(funnel_packet_menu_callback packet_callback);
    void setPacketData(GPtrArray* finfos);
    void addToMenu(QMenu * ctx_menu, QHash<QString, QMenu *> &menuTextToMenus);
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
    void *callback_data_;
    bool retap_;
    funnel_packet_menu_callback packetCallback_;
    GPtrArray* packetData_;
    QSet<QString> packetRequiredFields_;
};

class FunnelConsoleAction : public FunnelAction
{
    Q_OBJECT
public:
    FunnelConsoleAction(QString name, funnel_console_eval_cb_t eval_cb,
                        funnel_console_open_cb_t open_cb,
                        funnel_console_close_cb_t close_cb,
                        void *callback_data, QObject *parent);
    ~FunnelConsoleAction();
    virtual void triggerCallback();

private:
    QString title_;
    funnel_console_eval_cb_t eval_cb_;
    funnel_console_open_cb_t open_cb_;
    funnel_console_close_cb_t close_cb_;
    void *callback_data_;
    QPointer<IOConsoleDialog> dialog_;
};

extern "C" {
    void funnel_statistics_reload_menus(void);
    void funnel_statistics_load_packet_menus(void);
    void funnel_statistics_load_console_menus(void);
    bool funnel_statistics_packet_menus_modified(void);
} // extern "C"

#endif // FUNNELSTATISTICS_H
