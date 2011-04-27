/* wspy_register.c
 *
 * $Id$
 *
 * Wireshark Protocol Python Binding
 *
 * Copyright (c) 2009 by Sebastien Tandel <sebastien [AT] tandel [dot] be>
 * Copyright (c) 2001 by Gerald Combs <gerald@wireshark.org>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_PYTHON
#include <Python.h>

#include <glib.h>

#include <stdio.h>

#include "epan.h"
#include "proto.h"
#include "packet.h"
#include "tvbuff.h"
#include "filesystem.h"

#include "wspy_register.h"

/* hash table containing all the registered python dissectors */
GHashTable * g_py_dissectors=NULL;

/**
 * Global objects that python method dissect() will get. Avoid to write a
 * function for each proto_tree*.
 * Is it the only way to do that? I can't believe it ... think about it
 */
tvbuff_t * g_tvb = NULL;
packet_info * g_pinfo = NULL;
proto_tree * g_tree = NULL;


/* Initialization of the Python Interpreter */
static inline
void wspy_init(void)
{
  Py_Initialize();
}

/* Finalization of the Python Interpreter */
static inline
void wspy_finalize(void)
{
  Py_Finalize();
}

/*const char * py_dissector_short_desc(PyObject * py_dissector)
{
}*/

/**
 * Returns the __str__ of the python object
 */
char * py_dissector_name(PyObject * py_dissector)
{
  PyObject * py_object_name;

  assert(py_dissector);
  py_object_name = PyObject_Str(py_dissector);

  return PyString_AS_STRING(py_object_name);
}

/**
 * Register the dissector
 */
void py_dissector_register(PyObject * py_dissector, char * py_name, register_cb cb, gpointer client_data)
{
/*  const char * py_name; */

  /* Get the name of the dissector */
/*  py_name = py_dissector_name(py_dissector); */

  /* Register dissector in register_cb */
  if (cb)
    (*cb)(RA_REGISTER, py_name, client_data);

  /**
   * Register protocol, fields, subtrees
   *
   * Done by calling register method of the object
   */
  PyObject_CallMethod(py_dissector, "register_protocol", NULL);

}

static const char *get_py_register_file(void)
{
  static const char * wspython_register_file = NULL;

  if (!wspython_register_file) {
#ifdef _WIN32
      wspython_register_file = g_strdup_printf("%s\\register-dissector.py", get_wspython_dir());
#else
      wspython_register_file = g_strdup_printf("%s/register-dissector.py", get_wspython_dir());
#endif /* _WIN32 */
  }
  return wspython_register_file;
}

/**
 * Finds out all the python dissectors and register them
 */
void register_all_py_protocols_func(register_cb cb _U_, gpointer client_data _U_)
{
  FILE * py_reg;
  PyObject * global_dict, * main_module, * register_fn;
  PyObject * py_dissectors, * py_dissector;
  PyObject * py_args;
  Py_ssize_t index;
  char * name;

  /* intialize the hash table where all the python dissectors are kept */
  g_py_dissectors = g_hash_table_new(g_str_hash, g_str_equal);

  /* STA TODO : init only if prefs is enabled */
  wspy_init();

  /* load the python register module */
  py_reg = fopen(get_py_register_file(), "r");
  if (py_reg == NULL) {
    printf("no register file %s\n", get_py_register_file());
    return;
  }
  PyRun_SimpleFile(py_reg, get_py_register_file());

  /* Getting the global symbols from the python register module */
  main_module = PyImport_AddModule("__main__");
  global_dict = PyModule_GetDict(main_module);

  /* Get the python register function */
  register_fn = PyDict_GetItemString(global_dict, "register_dissectors");

  /* Execute the python register function */
  /* This function returns a sequence of python dissectors objects */
  py_args = Py_BuildValue("(s)", get_wspython_dir());
  py_dissectors = PyObject_CallObject(register_fn, py_args);

  /* Check that the py_dissectors is really a sequence */
  if (!py_dissectors || !PySequence_Check(py_dissectors)) {
    printf("Python dissectors not registered ...\n");
    return;
  }

  /**
   * For each dissector, register it in cb and registers all fields, subtrees,
   * protocol name, etc ...
   */
  for (index = 0; (py_dissector = PySequence_GetItem(py_dissectors, index)); index++)
  {
    name = py_dissector_name(py_dissector);
    py_dissector_register(py_dissector, name, cb, client_data);
    g_hash_table_insert(g_py_dissectors, (gpointer*)name, py_dissector);
  }
}

tvbuff_t *py_tvbuff(void)
{
  return g_tvb;
}

packet_info * py_pinfo(void)
{
  return g_pinfo;
}

proto_tree * py_tree(void)
{
  return g_tree;
}

/*
 * Generic Python Dissector
 *
 * Search the correct PyObject dissector based on
 * pinfo->current_proto in the hash table py_dissectors.
 *
 * We then call the method "dissect" of this PyObject.
 */
void py_dissect(tvbuff_t * tvb, packet_info * pinfo,
    proto_tree * tree)
{
  PyObject * py_dissector;

  /* printf("pinfo->current_proto : %s\n", pinfo->current_proto); */
  /* NOTE => pinfo->current_proto == "HomePlug" */

  g_tree = tree;
  g_pinfo = pinfo;
  g_tvb = tvb;

  py_dissector = g_hash_table_lookup(g_py_dissectors, pinfo->current_proto);
  assert(py_dissector);

  PyObject_CallMethod(py_dissector, "pre_dissect", NULL);
}

/*
 * Return the pointer to the generic python dissector
 *
 * One could think that it could be a PyCObject but it is a
 * workaround because ctypes is used and it complains later -not
 * knowing how to conver the parameter - in the Python code when
 * calling back a C function with a PyCObject as parameter
 */
dissector_t py_generic_dissector(void)
{
  return &py_dissect;
}

struct SRegisterHandoffsForeach {
  register_cb cb;
  gpointer client_data;
};

static void register_all_py_handoffs_foreach(gpointer key _U_, gpointer value, gpointer user_data)
{
  PyObject * py_dissector = (PyObject *)value;
  struct SRegisterHandoffsForeach *rhf = (struct SRegisterHandoffsForeach*)user_data;

  /* STA TODO : it's the short_desc field ... not really the filter field! */
  char * handoff_name = g_strdup_printf("handoff_%s", py_dissector_name(py_dissector));

  if (rhf->cb)
    (*(rhf->cb))(RA_HANDOFF, handoff_name, rhf->client_data);

  PyObject_CallMethod(py_dissector, "register_handoff", NULL);
}

/**
 * Finalize the registration of the python protocol dissectors
 */
void
register_all_py_handoffs_func(register_cb cb, gpointer client_data)
{
  struct SRegisterHandoffsForeach rhf;

  rhf.cb = cb;
  rhf.client_data = client_data;

  g_hash_table_foreach(g_py_dissectors, register_all_py_handoffs_foreach, &rhf);
}

#endif /* HAVE_PYTHON */
