/********************************************************************************
** Form generated from reading UI file 'search_frame.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_SEARCH_FRAME_H
#define UI_SEARCH_FRAME_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include "accordion_frame.h"
#include "widgets/syntax_line_edit.h"

QT_BEGIN_NAMESPACE

class Ui_SearchFrame
{
public:
    QHBoxLayout *horizontalLayout;
    QSpacerItem *horizontalSpacer_3;
    QComboBox *searchInComboBox;
    QSpacerItem *horizontalSpacer_2;
    QComboBox *charEncodingComboBox;
    QCheckBox *caseCheckBox;
    QSpacerItem *horizontalSpacer;
    QComboBox *searchTypeComboBox;
    SyntaxLineEdit *searchLineEdit;
    QPushButton *findButton;
    QPushButton *cancelButton;

    void setupUi(AccordionFrame *SearchFrame)
    {
        if (SearchFrame->objectName().isEmpty())
            SearchFrame->setObjectName(QString::fromUtf8("SearchFrame"));
        SearchFrame->resize(1026, 34);
        SearchFrame->setFrameShape(QFrame::NoFrame);
        SearchFrame->setFrameShadow(QFrame::Plain);
        horizontalLayout = new QHBoxLayout(SearchFrame);
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        horizontalLayout->setContentsMargins(-1, 0, -1, 0);
        horizontalSpacer_3 = new QSpacerItem(40, 20, QSizePolicy::Fixed, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_3);

        searchInComboBox = new QComboBox(SearchFrame);
        searchInComboBox->addItem(QString());
        searchInComboBox->addItem(QString());
        searchInComboBox->addItem(QString());
        searchInComboBox->setObjectName(QString::fromUtf8("searchInComboBox"));

        horizontalLayout->addWidget(searchInComboBox);

        horizontalSpacer_2 = new QSpacerItem(20, 10, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_2);

        charEncodingComboBox = new QComboBox(SearchFrame);
        charEncodingComboBox->addItem(QString());
        charEncodingComboBox->addItem(QString());
        charEncodingComboBox->addItem(QString());
        charEncodingComboBox->setObjectName(QString::fromUtf8("charEncodingComboBox"));

        horizontalLayout->addWidget(charEncodingComboBox);

        caseCheckBox = new QCheckBox(SearchFrame);
        caseCheckBox->setObjectName(QString::fromUtf8("caseCheckBox"));

        horizontalLayout->addWidget(caseCheckBox);

        horizontalSpacer = new QSpacerItem(20, 10, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);

        searchTypeComboBox = new QComboBox(SearchFrame);
        searchTypeComboBox->addItem(QString());
        searchTypeComboBox->addItem(QString());
        searchTypeComboBox->addItem(QString());
        searchTypeComboBox->addItem(QString());
        searchTypeComboBox->setObjectName(QString::fromUtf8("searchTypeComboBox"));

        horizontalLayout->addWidget(searchTypeComboBox);

        searchLineEdit = new SyntaxLineEdit(SearchFrame);
        searchLineEdit->setObjectName(QString::fromUtf8("searchLineEdit"));
        QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        sizePolicy.setHorizontalStretch(1);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(searchLineEdit->sizePolicy().hasHeightForWidth());
        searchLineEdit->setSizePolicy(sizePolicy);

        horizontalLayout->addWidget(searchLineEdit);

        findButton = new QPushButton(SearchFrame);
        findButton->setObjectName(QString::fromUtf8("findButton"));
        findButton->setMaximumSize(QSize(16777215, 27));

        horizontalLayout->addWidget(findButton);

        cancelButton = new QPushButton(SearchFrame);
        cancelButton->setObjectName(QString::fromUtf8("cancelButton"));
        cancelButton->setMaximumSize(QSize(16777215, 27));

        horizontalLayout->addWidget(cancelButton);

        horizontalLayout->setStretch(0, 3);
        horizontalLayout->setStretch(7, 1);

        retranslateUi(SearchFrame);

        findButton->setDefault(true);


        QMetaObject::connectSlotsByName(SearchFrame);
    } // setupUi

    void retranslateUi(AccordionFrame *SearchFrame)
    {
        SearchFrame->setWindowTitle(QApplication::translate("SearchFrame", "Frame", nullptr));
        searchInComboBox->setItemText(0, QApplication::translate("SearchFrame", "Packet list", nullptr));
        searchInComboBox->setItemText(1, QApplication::translate("SearchFrame", "Packet details", nullptr));
        searchInComboBox->setItemText(2, QApplication::translate("SearchFrame", "Packet bytes", nullptr));

#ifndef QT_NO_TOOLTIP
        searchInComboBox->setToolTip(QApplication::translate("SearchFrame", "<html><head/><body><p>Search the Info column of the packet list (summary pane), decoded packet display labels (tree view pane) or the ASCII-converted packet data (hex view pane).</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        charEncodingComboBox->setItemText(0, QApplication::translate("SearchFrame", "Narrow & Wide", nullptr));
        charEncodingComboBox->setItemText(1, QApplication::translate("SearchFrame", "Narrow (UTF-8 / ASCII)", nullptr));
        charEncodingComboBox->setItemText(2, QApplication::translate("SearchFrame", "Wide (UTF-16)", nullptr));

#ifndef QT_NO_TOOLTIP
        charEncodingComboBox->setToolTip(QApplication::translate("SearchFrame", "<html><head/><body><p>Search for strings containing narrow (UTF-8 and ASCII) or wide (UTF-16) characters.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        caseCheckBox->setText(QApplication::translate("SearchFrame", "Case sensitive", nullptr));
        searchTypeComboBox->setItemText(0, QApplication::translate("SearchFrame", "Display filter", nullptr));
        searchTypeComboBox->setItemText(1, QApplication::translate("SearchFrame", "Hex value", nullptr));
        searchTypeComboBox->setItemText(2, QApplication::translate("SearchFrame", "String", nullptr));
        searchTypeComboBox->setItemText(3, QApplication::translate("SearchFrame", "Regular Expression", nullptr));

#ifndef QT_NO_TOOLTIP
        searchTypeComboBox->setToolTip(QApplication::translate("SearchFrame", "<html><head/><body><p>Search for data using display filter syntax (e.g. ip.addr==10.1.1.1), a hexadecimal string (e.g. fffffda5), a plain string (e.g. My String) or a regular expression (e.g. colou?r).</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        findButton->setText(QApplication::translate("SearchFrame", "Find", nullptr));
        cancelButton->setText(QApplication::translate("SearchFrame", "Cancel", nullptr));
    } // retranslateUi

};

namespace Ui {
    class SearchFrame: public Ui_SearchFrame {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_SEARCH_FRAME_H
