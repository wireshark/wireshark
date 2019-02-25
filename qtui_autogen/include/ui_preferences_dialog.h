/********************************************************************************
** Form generated from reading UI file 'preferences_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_PREFERENCES_DIALOG_H
#define UI_PREFERENCES_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QFrame>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QSplitter>
#include <QtWidgets/QStackedWidget>
#include <QtWidgets/QTreeView>
#include <QtWidgets/QVBoxLayout>
#include "capture_preferences_frame.h"
#include "column_preferences_frame.h"
#include "font_color_preferences_frame.h"
#include "layout_preferences_frame.h"
#include "main_window_preferences_frame.h"
#include "rsa_keys_frame.h"
#include "uat_frame.h"
#include "widgets/pref_module_view.h"

QT_BEGIN_NAMESPACE

class Ui_PreferencesDialog
{
public:
    QVBoxLayout *verticalLayout;
    QSplitter *splitter;
    PrefModuleTreeView *prefsView;
    QStackedWidget *stackedWidget;
    MainWindowPreferencesFrame *appearanceFrame;
    LayoutPreferencesFrame *layoutFrame;
    ColumnPreferencesFrame *columnFrame;
    FontColorPreferencesFrame *fontandcolorFrame;
    CapturePreferencesFrame *captureFrame;
    UatFrame *expertFrame;
    UatFrame *filterExpressonsFrame;
    RsaKeysFrame *rsaKeysFrame;
    QFrame *advancedFrame;
    QVBoxLayout *verticalLayout_2;
    QHBoxLayout *horizontalLayout_2;
    QLabel *label;
    QLineEdit *advancedSearchLineEdit;
    QSpacerItem *horizontalSpacer;
    QTreeView *advancedView;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *PreferencesDialog)
    {
        if (PreferencesDialog->objectName().isEmpty())
            PreferencesDialog->setObjectName(QString::fromUtf8("PreferencesDialog"));
        PreferencesDialog->resize(680, 475);
        verticalLayout = new QVBoxLayout(PreferencesDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        splitter = new QSplitter(PreferencesDialog);
        splitter->setObjectName(QString::fromUtf8("splitter"));
        splitter->setOrientation(Qt::Horizontal);
        prefsView = new PrefModuleTreeView(splitter);
        prefsView->setObjectName(QString::fromUtf8("prefsView"));
        QSizePolicy sizePolicy(QSizePolicy::Preferred, QSizePolicy::MinimumExpanding);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(prefsView->sizePolicy().hasHeightForWidth());
        prefsView->setSizePolicy(sizePolicy);
        prefsView->setUniformRowHeights(true);
        prefsView->setHeaderHidden(true);
        prefsView->setSortingEnabled(true);
        splitter->addWidget(prefsView);
        stackedWidget = new QStackedWidget(splitter);
        stackedWidget->setObjectName(QString::fromUtf8("stackedWidget"));
        QSizePolicy sizePolicy1(QSizePolicy::MinimumExpanding, QSizePolicy::Preferred);
        sizePolicy1.setHorizontalStretch(0);
        sizePolicy1.setVerticalStretch(0);
        sizePolicy1.setHeightForWidth(stackedWidget->sizePolicy().hasHeightForWidth());
        stackedWidget->setSizePolicy(sizePolicy1);
        appearanceFrame = new MainWindowPreferencesFrame();
        appearanceFrame->setObjectName(QString::fromUtf8("appearanceFrame"));
        stackedWidget->addWidget(appearanceFrame);
        layoutFrame = new LayoutPreferencesFrame();
        layoutFrame->setObjectName(QString::fromUtf8("layoutFrame"));
        stackedWidget->addWidget(layoutFrame);
        columnFrame = new ColumnPreferencesFrame();
        columnFrame->setObjectName(QString::fromUtf8("columnFrame"));
        stackedWidget->addWidget(columnFrame);
        fontandcolorFrame = new FontColorPreferencesFrame();
        fontandcolorFrame->setObjectName(QString::fromUtf8("fontandcolorFrame"));
        stackedWidget->addWidget(fontandcolorFrame);
        captureFrame = new CapturePreferencesFrame();
        captureFrame->setObjectName(QString::fromUtf8("captureFrame"));
        stackedWidget->addWidget(captureFrame);
        expertFrame = new UatFrame();
        expertFrame->setObjectName(QString::fromUtf8("expertFrame"));
        stackedWidget->addWidget(expertFrame);
        filterExpressonsFrame = new UatFrame();
        filterExpressonsFrame->setObjectName(QString::fromUtf8("filterExpressonsFrame"));
        stackedWidget->addWidget(filterExpressonsFrame);
        rsaKeysFrame = new RsaKeysFrame();
        rsaKeysFrame->setObjectName(QString::fromUtf8("rsaKeysFrame"));
        stackedWidget->addWidget(rsaKeysFrame);
        advancedFrame = new QFrame();
        advancedFrame->setObjectName(QString::fromUtf8("advancedFrame"));
        verticalLayout_2 = new QVBoxLayout(advancedFrame);
        verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        label = new QLabel(advancedFrame);
        label->setObjectName(QString::fromUtf8("label"));

        horizontalLayout_2->addWidget(label);

        advancedSearchLineEdit = new QLineEdit(advancedFrame);
        advancedSearchLineEdit->setObjectName(QString::fromUtf8("advancedSearchLineEdit"));

        horizontalLayout_2->addWidget(advancedSearchLineEdit);

        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer);


        verticalLayout_2->addLayout(horizontalLayout_2);

        advancedView = new QTreeView(advancedFrame);
        advancedView->setObjectName(QString::fromUtf8("advancedView"));
        advancedView->setIndentation(0);
        advancedView->setUniformRowHeights(true);

        verticalLayout_2->addWidget(advancedView);

        stackedWidget->addWidget(advancedFrame);
        splitter->addWidget(stackedWidget);

        verticalLayout->addWidget(splitter);

        buttonBox = new QDialogButtonBox(PreferencesDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Help|QDialogButtonBox::Ok);

        verticalLayout->addWidget(buttonBox);


        retranslateUi(PreferencesDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), PreferencesDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), PreferencesDialog, SLOT(reject()));

        stackedWidget->setCurrentIndex(6);


        QMetaObject::connectSlotsByName(PreferencesDialog);
    } // setupUi

    void retranslateUi(QDialog *PreferencesDialog)
    {
        label->setText(QApplication::translate("PreferencesDialog", "Search:", nullptr));
        Q_UNUSED(PreferencesDialog);
    } // retranslateUi

};

namespace Ui {
    class PreferencesDialog: public Ui_PreferencesDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_PREFERENCES_DIALOG_H
