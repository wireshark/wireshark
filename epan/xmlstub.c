/* xmlstub.c
 * Routines to parse XML files using libxml2.  This stub
 * exists so that the library can be loaded on systems that
 * have it.
 *
 * $Id$
 *
 * Copyright (c) 2001 by David Frascone <dave@frascone.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998-2001 Gerald Combs
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <glib.h>
#include <gmodule.h>
#include <epan/report_err.h>

/* XML Stub routines */
#define IN_XMLSTUB
#include "xmlstub.h"

/*
 * This routine will dynamically load libxml2 and will populate the
 * XmlStub pointer structure.
 *
 * On any error, it will return non-zero, and it should be assumed that
 * the current platform does not have dynamic library support, or does
 * not have libxml2 installed.
 */
int
loadLibXML(void)
{
	GModule *handle;
	gpointer symbol;
	int error=FALSE;

	if (XmlStubInitialized) {
		/* Did you ever get the feeling you've been here before? */

		/*
		 * This is not thread safe.  With threads, we'd need to
		 * synchronize all this so two threads can't initialize at once.
		 */
		return 0;
	}

	/* Check to see if gmodule is supported */
	if (!g_module_supported()) {
		g_warning("XMLStub: Modules are not supported.  Not initializing XML Stub");
		return (-1);
	}

	/* open the dll.  Is this named something different
	 * under windows?  Perhaps we should check . . .
	 */
	if ((handle = g_module_open(XML_LIBRARY, G_MODULE_BIND_LAZY)) == NULL) {
		report_failure("XMLStub: Unable to open module " XML_LIBRARY );
		return (-1);
	}

	/*
	 * Now that the library is open, copy all our relevant
	 * function pointers and integer pointers into our structure.
	 */
	if (!g_module_symbol(handle, "xmlParseFile", &symbol)) {
		g_warning("Unable to find \"xmlParseFile\"");
		error=TRUE;
	}
	XmlStub.xmlParseFile= (xmlDocPtr(*)(const char *))symbol;

	if (!g_module_symbol(handle, "xmlStrcmp", &symbol)) {
		g_warning("Unable to find \"xmlStrcmp\"");
		error=TRUE;
	}
	XmlStub.xmlStrcmp= (int (*)(const xmlChar *, const xmlChar *))symbol;

	if (!g_module_symbol(handle, "xmlCreatePushParserCtxt", &symbol)) {
		g_warning("Unable to find \"xmlCreatePushParserCtxt\"");
		error=TRUE;
	}
    XmlStub.xmlCreatePushParserCtxt=(xmlParserCtxtPtr (*)
									 (xmlSAXHandlerPtr, void *, const char *,
									  int, const char *)) symbol;

	if (!g_module_symbol(handle, "xmlParseChunk", &symbol)) {
		g_warning("Unable to find \"xmlParseChunk\"");
		error=TRUE;
	}
	XmlStub.xmlParseChunk=(int (*)(xmlParserCtxtPtr, const char *, int, int))symbol;

	if (!g_module_symbol(handle, "xmlFreeParserCtxt", &symbol)) {
		g_warning("Unable to find \"xmlFreeParserCtxt\"");
		error=TRUE;
	}
	XmlStub.xmlFreeParserCtxt=(void (*)(xmlParserCtxtPtr))symbol;

	if (!g_module_symbol(handle, "xmlDocGetRootElement", &symbol)) {
		g_warning("Unable to find \"xmlDocGetRootElement\"");
		error=TRUE;
	}
	XmlStub.xmlDocGetRootElement=(xmlNodePtr(*)(xmlDocPtr))symbol;

	if (!g_module_symbol(handle, "xmlFreeDoc", &symbol)) {
		g_warning("Unable to find \"xmlFreeDoc\"");
		error=TRUE;
	}
	XmlStub.xmlFreeDoc=(void (*)(xmlDocPtr))symbol;

	if (!g_module_symbol(handle, "xmlNodeListGetString", &symbol)) {
		g_warning("Unable to find \"xmlNodeListGetString\"");
		error=TRUE;
	}
	XmlStub.xmlNodeListGetString=(char * (*)(xmlDocPtr, xmlNodePtr, int))symbol;

	if (!g_module_symbol(handle, "xmlGetProp", &symbol)) {
		g_warning("Unable to find \"xmlGetProp\"");
		error=TRUE;
	}
	XmlStub.xmlGetProp=(char * (*)(xmlNodePtr, char *))symbol;

	if (!g_module_symbol(handle, "xmlKeepBlanksDefault", &symbol)) {
		g_warning("Unable to find \"xmlKeepBlanksDefault\"");
		error=TRUE;
	}
	XmlStub.xmlKeepBlanksDefault=(int(*)(int))symbol;

	if (!g_module_symbol(handle, "xmlSubstituteEntitiesDefault", &symbol)) {
		g_warning("Unable to find \"xmlSubstituteEntitiesDefault\"");
		error=TRUE;
	}
	XmlStub.xmlSubstituteEntitiesDefault=(int(*)(int))symbol;

#ifdef ETHEREAL_XML_DO_VALIDITY_CHECKING
  if (!g_module_symbol(handle, "xmlDoValidityCheckingDefaultValue", &symbol)) {
		g_warning("Unable to find \"xmlDoValidityCheckingDefaultValue\"");
		error=TRUE;
	}
	XmlStub.xmlDoValidityCheckingDefaultValue = (int *)symbol;
#endif

	/*
	 * Return if any of the above functions set our error flag.
	 * A flag was used, instead of returning immediately, so
	 * that *all* unresolved symbols would be printed.
	 */
	if (error) {
		g_module_close(handle);
		return (-1);
	}
	/* Set our global so that we don't try to load twice */
	XmlStubInitialized=1;

	return 0; /* Success! */

} /* loadLibXML */
