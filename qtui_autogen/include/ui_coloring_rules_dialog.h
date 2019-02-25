/********************************************************************************
** Form generated from reading UI file 'coloring_rules_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_COLORING_RULES_DIALOG_H
#define UI_COLORING_RULES_DIALOG_H

#include <QtCore/QVariant>
#include <QtGui/QIcon>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QToolButton>
#include <QtWidgets/QVBoxLayout>
#include "widgets/elided_label.h"
#include "widgets/tabnav_tree_view.h"

QT_BEGIN_NAMESPACE

class Ui_ColoringRulesDialog
{
public:
    QVBoxLayout *verticalLayout;
    TabnavTreeView *coloringRulesTreeView;
    QLabel *hintLabel;
    QHBoxLayout *horizontalLayout;
    QToolButton *newToolButton;
    QToolButton *deleteToolButton;
    QToolButton *copyToolButton;
    QToolButton *clearToolButton;
    QPushButton *fGPushButton;
    QPushButton *bGPushButton;
    QPushButton *displayFilterPushButton;
    QSpacerItem *horizontalSpacer;
    ElidedLabel *pathLabel;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *ColoringRulesDialog)
    {
        if (ColoringRulesDialog->objectName().isEmpty())
            ColoringRulesDialog->setObjectName(QString::fromUtf8("ColoringRulesDialog"));
        ColoringRulesDialog->resize(650, 480);
        verticalLayout = new QVBoxLayout(ColoringRulesDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        coloringRulesTreeView = new TabnavTreeView(ColoringRulesDialog);
        coloringRulesTreeView->setObjectName(QString::fromUtf8("coloringRulesTreeView"));
        coloringRulesTreeView->setSelectionMode(QAbstractItemView::ExtendedSelection);
        coloringRulesTreeView->setTextElideMode(Qt::ElideMiddle);
        coloringRulesTreeView->setRootIsDecorated(false);
        coloringRulesTreeView->setUniformRowHeights(true);
        coloringRulesTreeView->setItemsExpandable(false);
        coloringRulesTreeView->setExpandsOnDoubleClick(false);
        coloringRulesTreeView->setDragEnabled(true);
        coloringRulesTreeView->setDropIndicatorShown(true);
        coloringRulesTreeView->setDragDropMode(QAbstractItemView::InternalMove);

        verticalLayout->addWidget(coloringRulesTreeView);

        hintLabel = new QLabel(ColoringRulesDialog);
        hintLabel->setObjectName(QString::fromUtf8("hintLabel"));
        hintLabel->setWordWrap(true);

        verticalLayout->addWidget(hintLabel);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        newToolButton = new QToolButton(ColoringRulesDialog);
        newToolButton->setObjectName(QString::fromUtf8("newToolButton"));
        QIcon icon;
        icon.addFile(QString::fromUtf8(":/stock/plus-8.png"), QSize(), QIcon::Normal, QIcon::Off);
        newToolButton->setIcon(icon);

        horizontalLayout->addWidget(newToolButton);

        deleteToolButton = new QToolButton(ColoringRulesDialog);
        deleteToolButton->setObjectName(QString::fromUtf8("deleteToolButton"));
        QIcon icon1;
        icon1.addFile(QString::fromUtf8(":/stock/minus-8.png"), QSize(), QIcon::Normal, QIcon::Off);
        deleteToolButton->setIcon(icon1);
        deleteToolButton->setEnabled(false);

        horizontalLayout->addWidget(deleteToolButton);

        copyToolButton = new QToolButton(ColoringRulesDialog);
        copyToolButton->setObjectName(QString::fromUtf8("copyToolButton"));
        QIcon icon2;
        icon2.addFile(QString::fromUtf8(":/stock/copy-8.png"), QSize(), QIcon::Normal, QIcon::Off);
        copyToolButton->setIcon(icon2);
        copyToolButton->setEnabled(false);

        horizontalLayout->addWidget(copyToolButton);

        clearToolButton = new QToolButton(ColoringRulesDialog);
        clearToolButton->setObjectName(QString::fromUtf8("clearToolButton"));
        QIcon icon3;
        icon3.addFile(QString::fromUtf8(":/stock/delete_list.png"), QSize(), QIcon::Normal, QIcon::Off);
        clearToolButton->setIcon(icon3);
        clearToolButton->setEnabled(false);

        horizontalLayout->addWidget(clearToolButton);

        fGPushButton = new QPushButton(ColoringRulesDialog);
        fGPushButton->setObjectName(QString::fromUtf8("fGPushButton"));
        fGPushButton->setStyleSheet(QString::fromUtf8("QPushButton { border: 1px solid palette(Dark); }"));
        fGPushButton->setAutoDefault(false);
        fGPushButton->setFlat(true);
        fGPushButton->setVisible(false);

        horizontalLayout->addWidget(fGPushButton);

        bGPushButton = new QPushButton(ColoringRulesDialog);
        bGPushButton->setObjectName(QString::fromUtf8("bGPushButton"));
        bGPushButton->setStyleSheet(QString::fromUtf8("QPushButton { border: 1px solid palette(Dark); }"));
        bGPushButton->setAutoDefault(false);
        bGPushButton->setFlat(true);
        bGPushButton->setVisible(false);

        horizontalLayout->addWidget(bGPushButton);

        displayFilterPushButton = new QPushButton(ColoringRulesDialog);
        displayFilterPushButton->setObjectName(QString::fromUtf8("displayFilterPushButton"));
        displayFilterPushButton->setAutoDefault(false);
        displayFilterPushButton->setVisible(false);

        horizontalLayout->addWidget(displayFilterPushButton);

        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);

        pathLabel = new ElidedLabel(ColoringRulesDialog);
        pathLabel->setObjectName(QString::fromUtf8("pathLabel"));
        QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        sizePolicy.setHorizontalStretch(1);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(pathLabel->sizePolicy().hasHeightForWidth());
        pathLabel->setSizePolicy(sizePolicy);
        pathLabel->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        pathLabel->setOpenExternalLinks(true);

        horizontalLayout->addWidget(pathLabel);

        horizontalLayout->setStretch(8, 1);

        verticalLayout->addLayout(horizontalLayout);

        buttonBox = new QDialogButtonBox(ColoringRulesDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Help|QDialogButtonBox::Ok);

        verticalLayout->addWidget(buttonBox);


        retranslateUi(ColoringRulesDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), ColoringRulesDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), ColoringRulesDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(ColoringRulesDialog);
    } // setupUi

    void retranslateUi(QDialog *ColoringRulesDialog)
    {
        ColoringRulesDialog->setWindowTitle(QApplication::translate("ColoringRulesDialog", "Dialog", nullptr));
        hintLabel->setText(QApplication::translate("ColoringRulesDialog", "<small><i>A hint.</i></small>", nullptr));
#ifndef QT_NO_TOOLTIP
        newToolButton->setToolTip(QApplication::translate("ColoringRulesDialog", "Add a new coloring rule.", nullptr));
#endif // QT_NO_TOOLTIP
        newToolButton->setText(QString());
#ifndef QT_NO_TOOLTIP
        deleteToolButton->setToolTip(QApplication::translate("ColoringRulesDialog", "Delete this coloring rule.", nullptr));
#endif // QT_NO_TOOLTIP
        deleteToolButton->setText(QString());
#ifndef QT_NO_TOOLTIP
        copyToolButton->setToolTip(QApplication::translate("ColoringRulesDialog", "Duplicate this coloring rule.", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_TOOLTIP
        clearToolButton->setToolTip(QApplication::translate("ColoringRulesDialog", "Clear all coloring rules.", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_TOOLTIP
        fGPushButton->setToolTip(QApplication::translate("ColoringRulesDialog", "Set the foreground color for this rule.", nullptr));
#endif // QT_NO_TOOLTIP
        fGPushButton->setText(QApplication::translate("ColoringRulesDialog", "Foreground", nullptr));
#ifndef QT_NO_TOOLTIP
        bGPushButton->setToolTip(QApplication::translate("ColoringRulesDialog", "Set the background color for this rule.", nullptr));
#endif // QT_NO_TOOLTIP
        bGPushButton->setText(QApplication::translate("ColoringRulesDialog", "Background", nullptr));
#ifndef QT_NO_TOOLTIP
        displayFilterPushButton->setToolTip(QApplication::translate("ColoringRulesDialog", "Set the display filter using this rule.", nullptr));
#endif // QT_NO_TOOLTIP
        displayFilterPushButton->setText(QApplication::translate("ColoringRulesDialog", "Apply as filter", nullptr));
        pathLabel->setText(QString());
    } // retranslateUi

};

namespace Ui {
    class ColoringRulesDialog: public Ui_ColoringRulesDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_COLORING_RULES_DIALOG_H
