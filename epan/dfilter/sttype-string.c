/* $Id: sttype-string.c,v 1.1 2001/02/01 20:21:18 gram Exp $ */

#include "syntax-tree.h"

static gpointer
string_new(gpointer string)
{
	return (gpointer) g_strdup((char*) string);
}

static void
string_free(gpointer value)
{
	g_free(value);
}


void
sttype_register_string(void)
{
	static sttype_t string_type = {
		STTYPE_STRING,
		"STRING",
		string_new,
		string_free,
	};

	sttype_register(&string_type);
}
