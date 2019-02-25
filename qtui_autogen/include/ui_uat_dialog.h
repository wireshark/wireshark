/********************************************************************************
** Form generated from reading UI file 'uat_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_UAT_DIALOG_H
#define UI_UAT_DIALOG_H

#include <QtCore/QVariant>
#include <QtGui/QIcon>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QToolButton>
#include <QtWidgets/QVBoxLayout>
#include "widgets/elided_label.h"
#include "widgets/tabnav_tree_view.h"

QT_BEGIN_NAMESPACE

class Ui_UatDialog
{
public:
    QVBoxLayout *verticalLayout;
    TabnavTreeView *uatTreeView;
    QLabel *hintLabel;
    QHBoxLayout *horizontalLayout;
    QToolButton *newToolButton;
    QToolButton *deleteToolButton;
    QToolButton *copyToolButton;
    QToolButton *moveUpToolButton;
    QToolButton *moveDownToolButton;
    QToolButton *clearToolButton;
    ElidedLabel *pathLabel;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *UatDialog)
    {
        if (UatDialog->objectName().isEmpty())
            UatDialog->setObjectName(QString::fromUtf8("UatDialog"));
        UatDialog->resize(566, 403);
        verticalLayout = new QVBoxLayout(UatDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        uatTreeView = new TabnavTreeView(UatDialog);
        uatTreeView->setObjectName(QString::fromUtf8("uatTreeView"));

        verticalLayout->addWidget(uatTreeView);

        hintLabel = new QLabel(UatDialog);
        hintLabel->setObjectName(QString::fromUtf8("hintLabel"));
        hintLabel->setStyleSheet(QString::fromUtf8("QLabel { color: red; }"));
        hintLabel->setTextFormat(Qt::RichText);
        hintLabel->setWordWrap(true);

        verticalLayout->addWidget(hintLabel);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        newToolButton = new QToolButton(UatDialog);
        newToolButton->setObjectName(QString::fromUtf8("newToolButton"));
        QIcon icon;
        icon.addFile(QString::fromUtf8(":/stock/plus-8.png"), QSize(), QIcon::Normal, QIcon::Off);
        newToolButton->setIcon(icon);

        horizontalLayout->addWidget(newToolButton);

        deleteToolButton = new QToolButton(UatDialog);
        deleteToolButton->setObjectName(QString::fromUtf8("deleteToolButton"));
        QIcon icon1;
        icon1.addFile(QString::fromUtf8(":/stock/minus-8.png"), QSize(), QIcon::Normal, QIcon::Off);
        deleteToolButton->setIcon(icon1);
        deleteToolButton->setEnabled(false);

        horizontalLayout->addWidget(deleteToolButton);

        copyToolButton = new QToolButton(UatDialog);
        copyToolButton->setObjectName(QString::fromUtf8("copyToolButton"));
        QIcon icon2;
        icon2.addFile(QString::fromUtf8(":/stock/copy-8.png"), QSize(), QIcon::Normal, QIcon::Off);
        copyToolButton->setIcon(icon2);
        copyToolButton->setEnabled(false);

        horizontalLayout->addWidget(copyToolButton);

        moveUpToolButton = new QToolButton(UatDialog);
        moveUpToolButton->setObjectName(QString::fromUtf8("moveUpToolButton"));
        QIcon icon3;
        icon3.addFile(QString::fromUtf8(":/stock/arrow_up.png"), QSize(), QIcon::Normal, QIcon::Off);
        moveUpToolButton->setIcon(icon3);
        moveUpToolButton->setEnabled(false);

        horizontalLayout->addWidget(moveUpToolButton);

        moveDownToolButton = new QToolButton(UatDialog);
        moveDownToolButton->setObjectName(QString::fromUtf8("moveDownToolButton"));
        QIcon icon4;
        icon4.addFile(QString::fromUtf8(":/stock/arrow_down.png"), QSize(), QIcon::Normal, QIcon::Off);
        moveDownToolButton->setIcon(icon4);
        moveDownToolButton->setEnabled(false);

        horizontalLayout->addWidget(moveDownToolButton);

        clearToolButton = new QToolButton(UatDialog);
        clearToolButton->setObjectName(QString::fromUtf8("clearToolButton"));
        QIcon icon5;
        icon5.addFile(QString::fromUtf8(":/stock/delete_list.png"), QSize(), QIcon::Normal, QIcon::Off);
        clearToolButton->setIcon(icon5);
        clearToolButton->setEnabled(false);

        horizontalLayout->addWidget(clearToolButton);

        pathLabel = new ElidedLabel(UatDialog);
        pathLabel->setObjectName(QString::fromUtf8("pathLabel"));
        QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        sizePolicy.setHorizontalStretch(1);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(pathLabel->sizePolicy().hasHeightForWidth());
        pathLabel->setSizePolicy(sizePolicy);
        pathLabel->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        pathLabel->setOpenExternalLinks(true);

        horizontalLayout->addWidget(pathLabel);

        horizontalLayout->setStretch(6, 1);

        verticalLayout->addLayout(horizontalLayout);

        buttonBox = new QDialogButtonBox(UatDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Help|QDialogButtonBox::Ok);

        verticalLayout->addWidget(buttonBox);


        retranslateUi(UatDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), UatDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), UatDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(UatDialog);
    } // setupUi

    void retranslateUi(QDialog *UatDialog)
    {
        hintLabel->setText(QString());
#ifndef QT_NO_TOOLTIP
        newToolButton->setToolTip(QApplication::translate("UatDialog", "Create a new entry.", nullptr));
#endif // QT_NO_TOOLTIP
        newToolButton->setText(QString());
#ifndef QT_NO_TOOLTIP
        deleteToolButton->setToolTip(QApplication::translate("UatDialog", "Remove this entry.", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_TOOLTIP
        copyToolButton->setToolTip(QApplication::translate("UatDialog", "Copy this entry.", nullptr));
#endif // QT_NO_TOOLTIP
        copyToolButton->setText(QString());
#ifndef QT_NO_TOOLTIP
        moveUpToolButton->setToolTip(QApplication::translate("UatDialog", "Move entry up.", nullptr));
#endif // QT_NO_TOOLTIP
        moveUpToolButton->setText(QString());
#ifndef QT_NO_TOOLTIP
        moveDownToolButton->setToolTip(QApplication::translate("UatDialog", "Move entry down.", nullptr));
#endif // QT_NO_TOOLTIP
        moveDownToolButton->setText(QString());
#ifndef QT_NO_TOOLTIP
        clearToolButton->setToolTip(QApplication::translate("UatDialog", "Clear all entries.", nullptr));
#endif // QT_NO_TOOLTIP
        clearToolButton->setText(QString());
        pathLabel->setText(QString());
        Q_UNUSED(UatDialog);
    } // retranslateUi

};

namespace Ui {
    class UatDialog: public Ui_UatDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_UAT_DIALOG_H
