/* algo.h */
/* See Copyright Notice in the file LICENSE */
/* SPDX-License-Identifier: MIT */

#include "common.h"

#define REX_VERSION "Lrexlib " VERSION

/* Forward declarations */
/**
 * @brief Pushes the subject string to the Lua stack.
 *
 * @param L The Lua state.
 * @param argE Execution arguments containing the subject string.
 */
static void gmatch_pushsubject (lua_State *L, TArgExec *argE);

/**
 * @brief Executes a regex find operation.
 *
 * @param ud Userdata containing regex information.
 * @param argE Execution arguments.
 * @return Result of the find operation.
 */
static int findmatch_exec  (TUserdata *ud, TArgExec *argE);

/**
 * @brief Executes a regex split operation.
 *
 * @param ud Userdata containing regex information.
 * @param argE Execution arguments.
 * @param offset Starting offset for the search.
 * @return Result of the split operation.
 */
static int split_exec      (TUserdata *ud, TArgExec *argE, int offset);

/**
 * @brief Executes a regex substitution operation.
 *
 * @param ud Userdata containing regex information.
 * @param argE Execution arguments.
 * @param offset Starting offset for the search.
 * @return Result of the substitution operation.
 */
static int gsub_exec       (TUserdata *ud, TArgExec *argE, int offset);

/**
 * @brief Executes a regex global match operation.
 *
 * @param ud Userdata containing regex information.
 * @param argE Execution arguments.
 * @return Result of the global match operation.
 */
static int gmatch_exec     (TUserdata *ud, TArgExec *argE);

/**
 * @brief Compiles a regular expression.
 *
 * @param L Lua state.
 * @param argC Compilation arguments.
 * @param pud Pointer to user data for compiled regex.
 * @return Result of the compilation operation.
 */
static int compile_regex   (lua_State *L, const TArgComp *argC, TUserdata **pud);

/**
 * @brief Generates an error in Lua.
 *
 * @param L Lua state.
 * @param ud Pointer to user data.
 * @param errcode Error code.
 * @return Result of the error generation operation.
 */
static int generate_error  (lua_State *L, const TUserdata *ud, int errcode);

#if LUA_VERSION_NUM == 501
#  define ALG_ENVIRONINDEX LUA_ENVIRONINDEX
#else
#  define ALG_ENVIRONINDEX lua_upvalueindex(1)
#endif

#ifndef ALG_CHARSIZE
#  define ALG_CHARSIZE 1
#endif

#ifndef BUFFERZ_PUTREPSTRING
#  define BUFFERZ_PUTREPSTRING bufferZ_putrepstring
#endif

#ifndef ALG_GETCARGS
#  define ALG_GETCARGS(a,b,c)
#endif

#ifndef DO_NAMED_SUBPATTERNS
#define DO_NAMED_SUBPATTERNS(a,b,c)
#endif

#define METHOD_FIND  0
#define METHOD_MATCH 1
#define METHOD_EXEC  2
#define METHOD_TFIND 3


/**
 * @brief Retrieves an optional limit value from Lua state.
 *
 * This function checks the Lua stack at a given position for an optional limit value.
 * If the value is not provided, it returns GSUB_UNLIMITED. If a function is provided,
 * it returns GSUB_CONDITIONAL. If a number is provided, it ensures the number is non-negative
 * and returns it; otherwise, it returns 0. If the value is of an unsupported type, it raises a Lua error.
 *
 * @param L The Lua state.
 * @param pos The position on the stack to check for the limit value.
 * @return The limit value as an integer or GSUB_UNLIMITED/CONDTIONAL based on the input.
 */
static int OptLimit (lua_State *L, int pos) {
  if (lua_isnoneornil (L, pos))
    return GSUB_UNLIMITED;
  if (lua_isfunction (L, pos))
    return GSUB_CONDITIONAL;
  if (lua_isnumber (L, pos)) {
    int a = lua_tointeger (L, pos);
    return a < 0 ? 0 : a;
  }
  return luaL_typerror (L, pos, "number or function");
}


/**
 * @brief Retrieves the start offset for a given position and length.
 *
 * This function calculates the start offset based on the provided stack position
 * and length. If the start offset is positive, it decrements by one. If negative,
 * it adjusts based on the length divided by ALG_CHARSIZE, ensuring it does not go below zero.
 *
 * @param L Lua state.
 * @param stackpos Stack position for the start offset.
 * @param len Length used in calculations.
 * @return Adjusted start offset multiplied by ALG_CHARSIZE.
 */
static int get_startoffset(lua_State *L, int stackpos, size_t len) {
  int startoffset = (int)luaL_optinteger(L, stackpos, 1);
  if(startoffset > 0)
    startoffset--;
  else if(startoffset < 0) {
    startoffset += len/ALG_CHARSIZE;
    if(startoffset < 0)
      startoffset = 0;
  }
  return startoffset*ALG_CHARSIZE;
}


/**
 * @brief Retrieves a user data pointer from Lua state at a given position.
 *
 * This function checks if the value at the specified position in the Lua stack has a metatable matching ALG_ENVIRONINDEX.
 * If it does, it casts the userdata to TUserdata and returns it. Otherwise, it returns NULL.
 *
 * @param L The Lua state.
 * @param pos The position in the Lua stack where the value is located.
 * @return A pointer to the TUserdata if successful, otherwise NULL.
 */
static TUserdata* test_ud (lua_State *L, int pos)
{
  TUserdata *ud;
  if (lua_getmetatable(L, pos) &&
      lua_rawequal(L, -1, ALG_ENVIRONINDEX) &&
      (ud = (TUserdata *)lua_touserdata(L, pos)) != NULL) {
    lua_pop(L, 1);
    return ud;
  }
  return NULL;
}


/**
 * @brief Checks if the first argument on the Lua stack is a userdata of type TUserdata.
 *
 * If the argument is not a userdata of the expected type, it raises a type error.
 *
 * @param L The Lua state.
 * @return A pointer to the TUserdata if successful, otherwise NULL.
 */
static TUserdata* check_ud (lua_State *L)
{
  TUserdata *ud = test_ud(L, 1);
  if (ud == NULL) luaL_typerror(L, 1, REX_TYPENAME);
  return ud;
}


/**
 * @brief Checks if the Lua value at the given position is a string, table, or userdata.
 *
 * @param L The Lua state.
 * @param pos The position of the value to check.
 * @param argE Pointer to the TArgExec structure where the text and its length will be stored.
 */
static void check_subject (lua_State *L, int pos, TArgExec *argE)
{
  int stype;
  argE->text = lua_tolstring (L, pos, &argE->textlen);
  stype = lua_type (L, pos);
  if (stype != LUA_TSTRING && stype != LUA_TTABLE && stype != LUA_TUSERDATA) {
    luaL_typerror (L, pos, "string, table or userdata");
  } else if (argE->text == NULL) {
    int type;
    lua_getfield (L, pos, "topointer");
    if (lua_type (L, -1) != LUA_TFUNCTION)
      luaL_error (L, "subject has no topointer method");
    lua_pushvalue (L, pos);
    lua_call (L, 1, 1);
    type = lua_type (L, -1);
    if (type != LUA_TLIGHTUSERDATA)
      luaL_error (L, "subject's topointer method returned %s (expected lightuserdata)",
                  lua_typename (L, type));
    argE->text = (const char*) lua_touserdata (L, -1);
    lua_pop (L, 1);
#if LUA_VERSION_NUM == 501
    if (luaL_callmeta (L, pos, "__len")) {
      if (lua_type (L, -1) != LUA_TNUMBER)
        luaL_argerror (L, pos, "subject's length is not a number");
      argE->textlen = lua_tointeger (L, -1);
      lua_pop (L, 1);
    }
    else
      argE->textlen = lua_objlen (L, pos);
#else
    argE->textlen = luaL_len (L, pos);
#endif
  }
}

/**
 * @brief Checks if the provided Lua value at the specified position is a string or a userdata.
 *
 * If the value is a string, it sets the pattern and its length in the TArgComp structure.
 * If the value is a userdata, it attempts to retrieve a user data pointer and sets it in the TArgComp structure.
 * If neither is valid, it raises a type error.
 *
 * @param L The Lua state.
 * @param pos The position of the value on the Lua stack.
 * @param argC Pointer to the TArgComp structure where the result will be stored.
 */
static void check_pattern (lua_State *L, int pos, TArgComp *argC)
{
  if (lua_isstring (L, pos)) {
    argC->pattern = lua_tolstring (L, pos, &argC->patlen);
    argC->ud = NULL;
  }
  else if ((argC->ud = test_ud (L, pos)) == NULL)
    luaL_typerror(L, pos, "string or " REX_TYPENAME);
}

/**
 * @brief Checks arguments for the 'new' function.
 *
 * This function validates and extracts the pattern, flags, and additional arguments from the Lua stack.
 *
 * @param L The Lua state.
 * @param argC Pointer to the structure where the extracted arguments will be stored.
 */
static void checkarg_new (lua_State *L, TArgComp *argC) {
  argC->pattern = luaL_checklstring (L, 1, &argC->patlen);
  argC->cflags = ALG_GETCFLAGS (L, 2);
  ALG_GETCARGS (L, 3, argC);
}


/* function gsub (s, patt, f, [n], [cf], [ef], [larg...]) */

/**
 * @brief Checks arguments for the gsub function.
 *
 * Validates the input arguments for the gsub function, ensuring that the third argument is a string, table, or function.
 *
 * @param L Lua state.
 * @param argC Pointer to TArgComp structure for storing comparison arguments.
 * @param argE Pointer to TArgExec structure for storing execution arguments.
 */
static void checkarg_gsub (lua_State *L, TArgComp *argC, TArgExec *argE) {
  check_subject (L, 1, argE);
  check_pattern (L, 2, argC);
  lua_tostring (L, 3);    /* converts number (if any) to string */
  argE->reptype = lua_type (L, 3);
  if (argE->reptype != LUA_TSTRING && argE->reptype != LUA_TTABLE &&
      argE->reptype != LUA_TFUNCTION) {
    luaL_typerror (L, 3, "string, table or function");
  }
  argE->funcpos = 3;
  argE->funcpos2 = 4;
  argE->maxmatch = OptLimit (L, 4);
  argC->cflags = ALG_GETCFLAGS (L, 5);
  argE->eflags = (int)luaL_optinteger (L, 6, ALG_EFLAGS_DFLT);
  ALG_GETCARGS (L, 7, argC);
}


/* function count (s, patt, [cf], [ef], [larg...]) */

/**
 * @brief Checks the number of arguments for a function.
 *
 * This function verifies that the correct number of arguments are provided to a function.
 * It checks the subject, pattern, and other parameters based on the given argument count.
 *
 * @param L The Lua state.
 * @param argC Pointer to the TArgComp structure where pattern-related flags are stored.
 * @param argE Pointer to the TArgExec structure where execution-related flags are stored.
 */
static void checkarg_count (lua_State *L, TArgComp *argC, TArgExec *argE) {
  check_subject (L, 1, argE);
  check_pattern (L, 2, argC);
  argC->cflags = ALG_GETCFLAGS (L, 3);
  argE->eflags = (int)luaL_optinteger (L, 4, ALG_EFLAGS_DFLT);
  ALG_GETCARGS (L, 5, argC);
}


/* function find  (s, patt, [st], [cf], [ef], [larg...]) */
/* function match (s, patt, [st], [cf], [ef], [larg...]) */

/**
 * @brief Checks arguments for the find_func function.
 *
 * Validates and extracts parameters from the Lua stack to prepare for pattern matching operations.
 *
 * @param L The Lua state.
 * @param argC Pointer to a structure that will hold compilation arguments.
 * @param argE Pointer to a structure that will hold execution arguments.
 */
static void checkarg_find_func (lua_State *L, TArgComp *argC, TArgExec *argE) {
  check_subject (L, 1, argE);
  check_pattern (L, 2, argC);
  argE->startoffset = get_startoffset (L, 3, argE->textlen);
  argC->cflags = ALG_GETCFLAGS (L, 4);
  argE->eflags = (int)luaL_optinteger (L, 5, ALG_EFLAGS_DFLT);
  ALG_GETCARGS (L, 6, argC);
}


/* function gmatch (s, patt, [cf], [ef], [larg...]) */
/* function split  (s, patt, [cf], [ef], [larg...]) */

/**
 * @brief Checks arguments for the gmatch_split function.
 *
 * Validates and extracts parameters from the Lua stack to prepare for pattern matching operations.
 *
 * @param L The Lua state.
 * @param argC Pointer to the TArgComp structure where compiled pattern information will be stored.
 * @param argE Pointer to the TArgExec structure where execution flags will be stored.
 */
static void checkarg_gmatch_split (lua_State *L, TArgComp *argC, TArgExec *argE) {
  check_subject (L, 1, argE);
  check_pattern (L, 2, argC);
  argC->cflags = ALG_GETCFLAGS (L, 3);
  argE->eflags = (int)luaL_optinteger (L, 4, ALG_EFLAGS_DFLT);
  ALG_GETCARGS (L, 5, argC);
}


/* method r:tfind (s, [st], [ef]) */
/* method r:exec  (s, [st], [ef]) */
/* method r:find  (s, [st], [ef]) */
/* method r:match (s, [st], [ef]) */

/**
 * @brief Checks arguments for the find method.
 *
 * This function verifies and extracts necessary arguments from the Lua state for the find method.
 *
 * @param L The Lua state.
 * @param argE Pointer to the TArgExec structure where extracted arguments will be stored.
 * @param ud Pointer to a TUserdata pointer that will be set with the checked userdata.
 */
static void checkarg_find_method (lua_State *L, TArgExec *argE, TUserdata **ud) {
  *ud = check_ud (L);
  check_subject (L, 2, argE);
  argE->startoffset = get_startoffset (L, 3, argE->textlen);
  argE->eflags = (int)luaL_optinteger (L, 4, ALG_EFLAGS_DFLT);
}


/**
 * @brief Creates a new regular expression object.
 *
 * This function initializes a new regular expression object from the provided arguments and compiles it.
 *
 * @param L The Lua state.
 * @return Number of values pushed onto the stack.
 */
static int algf_new (lua_State *L) {
  TArgComp argC;
  checkarg_new (L, &argC);
  return compile_regex (L, &argC, NULL);
}

/**
 * @brief Pushes substrings from a regular expression match onto the Lua stack.
 *
 * This function iterates over the number of substrings specified in the user data
 * and pushes each substring onto the Lua stack. If there is not enough space on the
 * stack, it frees any associated free list and raises an error.
 *
 * @param L The Lua state to operate on.
 * @param ud User data containing information about the regular expression match.
 * @param text The original text that was matched against the regular expression.
 * @param freelist A pointer to a free list that may need to be freed if there is not enough stack space.
 */
static void push_substrings (lua_State *L, TUserdata *ud, const char *text,
                             TFreeList *freelist) {
  int i;
  if (lua_checkstack (L, ALG_NSUB(ud)) == 0) {
    if (freelist)
      freelist_free (freelist);
    luaL_error (L, "cannot add %d stack slots", ALG_NSUB(ud));
  }
  for (i = 1; i <= ALG_NSUB(ud); i++) {
    ALG_PUSHSUB_OR_FALSE (L, ud, text, i);
  }
}

/**
 * @brief Perform a global substitution on a string using a regular expression.
 *
 * This function takes a Lua state and performs a global substitution on a string
 * using a compiled regular expression. It returns the number of substitutions made.
 *
 * @param L The Lua state.
 * @return The number of substitutions made.
 */
static int algf_gsub (lua_State *L) {
  TUserdata *ud;
  TArgComp argC;
  TArgExec argE;
  int n_match = 0, n_subst = 0, st = 0, last_to = -1;
  TBuffer BufOut, BufRep, BufTemp, *pBuf = &BufOut;
  TFreeList freelist;
  /*------------------------------------------------------------------*/
  checkarg_gsub (L, &argC, &argE);
  if (argC.ud) {
    ud = (TUserdata*) argC.ud;
    lua_pushvalue (L, 2);
  }
  else compile_regex (L, &argC, &ud);
  freelist_init (&freelist);
  /*------------------------------------------------------------------*/
  if (argE.reptype == LUA_TSTRING) {
    buffer_init (&BufRep, 256, L, &freelist);
    BUFFERZ_PUTREPSTRING (&BufRep, argE.funcpos, ALG_NSUB(ud));
  }
  /*------------------------------------------------------------------*/
  if (argE.maxmatch == GSUB_CONDITIONAL) {
    buffer_init (&BufTemp, 1024, L, &freelist);
    pBuf = &BufTemp;
  }
  /*------------------------------------------------------------------*/
  buffer_init (&BufOut, 1024, L, &freelist);
  while ((argE.maxmatch < 0 || n_match < argE.maxmatch) && st <= (int)argE.textlen) {
    int from, to, res;
    int curr_subst = 0;
    res = gsub_exec (ud, &argE, st);
    if (ALG_NOMATCH (res)) {
      break;
    }
    else if (!ALG_ISMATCH (res)) {
      freelist_free (&freelist);
      return generate_error (L, ud, res);
    }
    from = ALG_BASE(st) + ALG_SUBBEG(ud,0);
    to = ALG_BASE(st) + ALG_SUBEND(ud,0);
    if (to == last_to) { /* discard an empty match adjacent to the previous match */
      if (st < (int)argE.textlen) { /* advance by 1 char (not replaced) */
        buffer_addlstring (&BufOut, argE.text + st, ALG_CHARSIZE);
        st += ALG_CHARSIZE;
        continue;
      }
      break;
    }
    last_to = to;
    ++n_match;
    if (st < from) {
      buffer_addlstring (&BufOut, argE.text + st, from - st);
#ifdef ALG_PULL
      st = from;
#endif
    }
    /*----------------------------------------------------------------*/
    if (argE.reptype == LUA_TSTRING) {
      size_t iter = 0, num;
      const char *str;
      while (bufferZ_next (&BufRep, &iter, &num, &str)) {
        if (str)
          buffer_addlstring (pBuf, str, num);
        else if (num == 0 || ALG_SUBVALID (ud,num))
          buffer_addlstring (pBuf, argE.text + ALG_BASE(st) + ALG_SUBBEG(ud,num), ALG_SUBLEN(ud,num));
      }
      curr_subst = 1;
    }
    /*----------------------------------------------------------------*/
    else if (argE.reptype == LUA_TTABLE) {
      if (ALG_NSUB(ud) > 0)
        ALG_PUSHSUB_OR_FALSE (L, ud, argE.text + ALG_BASE(st), 1);
      else
        lua_pushlstring (L, argE.text + from, to - from);
      lua_gettable (L, argE.funcpos);
    }
    /*----------------------------------------------------------------*/
    else if (argE.reptype == LUA_TFUNCTION) {
      int narg;
      lua_pushvalue (L, argE.funcpos);
      if (ALG_NSUB(ud) > 0) {
        push_substrings (L, ud, argE.text + ALG_BASE(st), &freelist);
        narg = ALG_NSUB(ud);
      }
      else {
        lua_pushlstring (L, argE.text + from, to - from);
        narg = 1;
      }
      if (0 != lua_pcall (L, narg, 1, 0)) {
        freelist_free (&freelist);
        return lua_error (L);  /* re-raise the error */
      }
    }
    /*----------------------------------------------------------------*/
    if (argE.reptype == LUA_TTABLE || argE.reptype == LUA_TFUNCTION) {
      if (lua_tostring (L, -1)) {
        buffer_addvalue (pBuf, -1);
        curr_subst = 1;
      }
      else if (!lua_toboolean (L, -1))
        buffer_addlstring (pBuf, argE.text + from, to - from);
      else {
        freelist_free (&freelist);
        luaL_error (L, "invalid replacement value (a %s)", luaL_typename (L, -1));
      }
      if (argE.maxmatch != GSUB_CONDITIONAL)
        lua_pop (L, 1);
    }
    /*----------------------------------------------------------------*/
    if (argE.maxmatch == GSUB_CONDITIONAL) {
      /* Call the function */
      lua_pushvalue (L, argE.funcpos2);
      lua_pushinteger (L, from/ALG_CHARSIZE + 1);
      lua_pushinteger (L, to/ALG_CHARSIZE);
      if (argE.reptype == LUA_TSTRING)
        buffer_pushresult (&BufTemp);
      else {
        lua_pushvalue (L, -4);
        lua_remove (L, -5);
      }
      if (0 != lua_pcall (L, 3, 2, 0)) {
        freelist_free (&freelist);
        lua_error (L);  /* re-raise the error */
      }
      /* Handle the 1-st return value */
      if (lua_isstring (L, -2)) {               /* coercion is allowed here */
        buffer_addvalue (&BufOut, -2);          /* rep2 */
        curr_subst = 1;
      }
      else if (lua_toboolean (L, -2))
        buffer_addbuffer (&BufOut, &BufTemp);   /* rep1 */
      else {
        buffer_addlstring (&BufOut, argE.text + from, to - from); /* "no" */
        curr_subst = 0;
      }
      /* Handle the 2-nd return value */
      if (lua_type (L, -1) == LUA_TNUMBER) {    /* no coercion is allowed here */
        int n = lua_tointeger (L, -1);
        if (n < 0)                              /* n */
          n = 0;
        argE.maxmatch = n_match + n;
      }
      else if (lua_toboolean (L, -1))           /* "yes to all" */
        argE.maxmatch = GSUB_UNLIMITED;
      else
        buffer_clear (&BufTemp);

      lua_pop (L, 2);
      if (argE.maxmatch != GSUB_CONDITIONAL)
        pBuf = &BufOut;
    }
    /*----------------------------------------------------------------*/
    n_subst += curr_subst;
    if (st < to) {
      st = to;
    }
    else if (st < (int)argE.textlen) {
      /* advance by 1 char (not replaced) */
      buffer_addlstring (&BufOut, argE.text + st, ALG_CHARSIZE);
      st += ALG_CHARSIZE;
    }
    else break;
  }
  /*------------------------------------------------------------------*/
  buffer_addlstring (&BufOut, argE.text + st, argE.textlen - st);
  buffer_pushresult (&BufOut);
  lua_pushinteger (L, n_match);
  lua_pushinteger (L, n_subst);
  freelist_free (&freelist);
  return 3;
}


/**
 * @brief Counts the number of matches for a given pattern in a text.
 *
 * This function takes a Lua state and arguments to count the occurrences of a pattern within a text.
 *
 * @param L The Lua state.
 * @return The number of matches found.
 */
static int algf_count (lua_State *L) {
  TUserdata *ud;
  TArgComp argC;
  TArgExec argE;
  int n_match = 0, st = 0, last_to = -1;
  /*------------------------------------------------------------------*/
  checkarg_count (L, &argC, &argE);
  if (argC.ud) {
    ud = (TUserdata*) argC.ud;
    lua_pushvalue (L, 2);
  }
  else compile_regex (L, &argC, &ud);
  /*------------------------------------------------------------------*/
  while (st <= (int)argE.textlen) {
    int to, res;
    res = gsub_exec (ud, &argE, st);
    if (ALG_NOMATCH (res)) {
      break;
    }
    else if (!ALG_ISMATCH (res)) {
      return generate_error (L, ud, res);
    }
    to = ALG_BASE(st) + ALG_SUBEND(ud,0);
    if (to == last_to) { /* discard an empty match adjacent to the previous match */
      if (st < (int)argE.textlen) { /* advance by 1 char */
        st += ALG_CHARSIZE;
        continue;
      }
      break;
    }
    last_to = to;
    ++n_match;
#ifdef ALG_PULL
    {
      int from = ALG_BASE(st) + ALG_SUBBEG(ud,0);
      if (st < from)
        st = from;
    }
#endif
    /*----------------------------------------------------------------*/
    if (st < to) {
      st = to;
    }
    else if (st < (int)argE.textlen) {
      /* advance by 1 char (not replaced) */
      st += ALG_CHARSIZE;
    }
    else break;
  }
  /*------------------------------------------------------------------*/
  lua_pushinteger (L, n_match);
  return 1;
}


/**
 * @brief Completes a generic find operation in Lua.
 *
 * This function is responsible for handling the completion of a find operation,
 * pushing offsets, captures, or a single substring based on the method and result.
 *
 * @param L The Lua state.
 * @param ud Userdata containing algorithm state.
 * @param argE Argument execution structure.
 * @param method The type of method (e.g., METHOD_FIND, METHOD_MATCH).
 * @param res Result of the find operation.
 * @return Number of values pushed onto the Lua stack.
 */
static int finish_generic_find (lua_State *L, TUserdata *ud, TArgExec *argE,
  int method, int res)
{
  if (ALG_ISMATCH (res)) {
    if (method == METHOD_FIND)
      ALG_PUSHOFFSETS (L, ud, ALG_BASE(argE->startoffset), 0);
    if (ALG_NSUB(ud))    /* push captures */
      push_substrings (L, ud, argE->text, NULL);
    else if (method != METHOD_FIND) {
      ALG_PUSHSUB (L, ud, argE->text, 0);
      return 1;
    }
    return (method == METHOD_FIND) ? ALG_NSUB(ud) + 2 : ALG_NSUB(ud);
  }
  else if (ALG_NOMATCH (res))
    return lua_pushnil (L), 1;
  else
    return generate_error (L, ud, res);
}


/**
 * @brief Generic find function for Lua bindings.
 *
 * This function is used to perform a generic find operation in Lua scripts using regular expressions.
 *
 * @param L The Lua state.
 * @param method The method type (e.g., METHOD_FIND, METHOD_MATCH).
 * @return Number of values pushed onto the Lua stack.
 */
static int generic_find_func (lua_State *L, int method) {
  TUserdata *ud;
  TArgComp argC;
  TArgExec argE;
  int res;

  checkarg_find_func (L, &argC, &argE);
  if (argE.startoffset > (int)argE.textlen)
    return lua_pushnil (L), 1;

  if (argC.ud) {
    ud = (TUserdata*) argC.ud;
    lua_pushvalue (L, 2);
  }
  else compile_regex (L, &argC, &ud);
  res = findmatch_exec (ud, &argE);
  return finish_generic_find (L, ud, &argE, method, res);
}


/**
 * @brief Finds a pattern in a string using Lua.
 *
 * @param L The Lua state.
 * @return The number of values pushed onto the stack.
 */
static int algf_find (lua_State *L) {
  return generic_find_func (L, METHOD_FIND);
}


/**
 * @brief Lua function to perform a match operation.
 *
 * This function is used to execute a match operation using a generic find function.
 *
 * @param L The Lua state.
 * @return The number of results on the stack.
 */
static int algf_match (lua_State *L) {
  return generic_find_func (L, METHOD_MATCH);
}


/**
 * @brief Iterate through matches of a regular expression.
 *
 * This function is used as an iterator in Lua to find all non-overlapping matches of a regular expression within a given text.
 *
 * @param L The Lua state.
 * @return Number of values pushed onto the stack (1 for the next match or 0 if no more matches).
 */
static int gmatch_iter (lua_State *L) {
  int last_end, res;
  TArgExec argE;
  TUserdata *ud    = (TUserdata*) lua_touserdata (L, lua_upvalueindex (1));
  argE.text        = lua_tolstring (L, lua_upvalueindex (2), &argE.textlen);
  argE.eflags      = lua_tointeger (L, lua_upvalueindex (3));
  argE.startoffset = lua_tointeger (L, lua_upvalueindex (4));
  last_end         = lua_tointeger (L, lua_upvalueindex (5));

  while (1) {
    if (argE.startoffset > (int)argE.textlen)
      return 0;
    res = gmatch_exec (ud, &argE);
    if (ALG_ISMATCH (res)) {
      int incr = 0;
      if (!ALG_SUBLEN(ud,0)) { /* no progress: prevent endless loop */
        if (last_end == ALG_BASE(argE.startoffset) + ALG_SUBEND(ud,0)) {
          argE.startoffset += ALG_CHARSIZE;
          continue;
        }
        incr = ALG_CHARSIZE;
      }
      last_end = ALG_BASE(argE.startoffset) + ALG_SUBEND(ud,0);
      lua_pushinteger(L, last_end + incr); /* update start offset */
      lua_replace (L, lua_upvalueindex (4));
      lua_pushinteger(L, last_end); /* update last end of match */
      lua_replace (L, lua_upvalueindex (5));
      /* push either captures or entire match */
      if (ALG_NSUB(ud)) {
        push_substrings (L, ud, argE.text, NULL);
        return ALG_NSUB(ud);
      }
      else {
        ALG_PUSHSUB (L, ud, argE.text, 0);
        return 1;
      }
    }
    else if (ALG_NOMATCH (res))
      return 0;
    else
      return generate_error (L, ud, res);
  }
}


/**
 * @brief Iterates through a string and splits it based on a regular expression.
 *
 * This function is used as an iterator in Lua to split a string into substrings
 * using a regular expression pattern. It returns the next substring each time
 * it is called until all substrings have been returned.
 *
 * @param L The Lua state.
 * @return Number of values pushed onto the stack (1 for the next substring).
 */
static int split_iter (lua_State *L) {
  int incr, last_end, newoffset, res;
  TArgExec argE;
  TUserdata *ud    = (TUserdata*) lua_touserdata (L, lua_upvalueindex (1));
  argE.text        = lua_tolstring (L, lua_upvalueindex (2), &argE.textlen);
  argE.eflags      = lua_tointeger (L, lua_upvalueindex (3));
  argE.startoffset = lua_tointeger (L, lua_upvalueindex (4));
  incr             = lua_tointeger (L, lua_upvalueindex (5));
  last_end         = lua_tointeger (L, lua_upvalueindex (6));

  if (incr < 0)
    return 0;

  while (1) {
    if ((newoffset = argE.startoffset + incr) > (int)argE.textlen)
      break;
    res = split_exec (ud, &argE, newoffset);
    if (ALG_ISMATCH (res)) {
      if (!ALG_SUBLEN(ud,0)) { /* no progress: prevent endless loop */
        if (last_end == ALG_BASE(argE.startoffset) + ALG_SUBEND(ud,0)) {
          incr += ALG_CHARSIZE;
          continue;
        }
      }
      lua_pushinteger(L, ALG_BASE(newoffset) + ALG_SUBEND(ud,0)); /* update start offset and last_end */
      lua_pushvalue (L, -1);
      lua_replace (L, lua_upvalueindex (4));
      lua_replace (L, lua_upvalueindex (6));
      lua_pushinteger (L, ALG_SUBLEN(ud,0) ? 0 : ALG_CHARSIZE);    /* update incr */
      lua_replace (L, lua_upvalueindex (5));
      /* push text preceding the match */
      lua_pushlstring (L, argE.text + argE.startoffset,
                       ALG_SUBBEG(ud,0) + ALG_BASE(newoffset) - argE.startoffset);
      /* push either captures or entire match */
      if (ALG_NSUB(ud)) {
        push_substrings (L, ud, argE.text + ALG_BASE(newoffset), NULL);
        return 1 + ALG_NSUB(ud);
      }
      else {
        ALG_PUSHSUB (L, ud, argE.text + ALG_BASE(newoffset), 0);
        return 2;
      }
    }
    else if (ALG_NOMATCH (res))
      break;
    else
      return generate_error (L, ud, res);
  }
  lua_pushinteger (L, -1);    /* mark as last iteration */
  lua_replace (L, lua_upvalueindex (5));   /* incr = -1 */
  lua_pushlstring (L, argE.text+argE.startoffset, argE.textlen-argE.startoffset);
  return 1;
}


/**
 * @brief Lua function to perform a global match using a regular expression.
 *
 * This function is used in Lua scripts to find all matches of a given pattern in a string.
 *
 * @param L The Lua state.
 * @return Number of results on the stack.
 */
static int algf_gmatch (lua_State *L)
{
  TArgComp argC;
  TArgExec argE;
  checkarg_gmatch_split (L, &argC, &argE);
  if (argC.ud)
    lua_pushvalue (L, 2);
  else
    compile_regex (L, &argC, NULL);           /* 1-st upvalue: ud */
  gmatch_pushsubject (L, &argE);              /* 2-nd upvalue: s  */
  lua_pushinteger (L, argE.eflags);           /* 3-rd upvalue: ef */
  lua_pushinteger (L, 0);                     /* 4-th upvalue: startoffset */
  lua_pushinteger (L, -1);                    /* 5-th upvalue: last end of match */
  lua_pushcclosure (L, gmatch_iter, 5);
  return 1;
}

/**
 * @brief Splits a string using a regular expression.
 *
 * This function splits a given string into substrings based on a specified regular expression pattern.
 *
 * @param L The Lua state.
 * @return The number of elements pushed onto the Lua stack.
 */
static int algf_split (lua_State *L)
{
  TArgComp argC;
  TArgExec argE;
  checkarg_gmatch_split (L, &argC, &argE);
  if (argC.ud)
    lua_pushvalue (L, 2);
  else
    compile_regex (L, &argC, NULL);           /* 1-st upvalue: ud */
  gmatch_pushsubject (L, &argE);              /* 2-nd upvalue: s  */
  lua_pushinteger (L, argE.eflags);           /* 3-rd upvalue: ef */
  lua_pushinteger (L, 0);                     /* 4-th upvalue: startoffset */
  lua_pushinteger (L, 0);                     /* 5-th upvalue: incr */
  lua_pushinteger (L, -1);                    /* 6-th upvalue: last_end */
  lua_pushcclosure (L, split_iter, 6);
  return 1;
}


/**
 * @brief Pushes a substring table onto the Lua stack.
 *
 * This function creates a new Lua table and populates it with substrings from the given text,
 * based on the number of substrings stored in the user data.
 *
 * @param L The Lua state to operate on.
 * @param ud The user data containing information about the substrings.
 * @param text The input text from which substrings are extracted.
 */
static void push_substring_table (lua_State *L, TUserdata *ud, const char *text) {
  int i;
  lua_newtable (L);
  for (i = 1; i <= ALG_NSUB(ud); i++) {
    ALG_PUSHSUB_OR_FALSE (L, ud, text, i);
    lua_rawseti (L, -2, i);
  }
}


/**
 * @brief Pushes an offset table onto the Lua stack.
 *
 * This function creates a new Lua table and populates it with start and end offsets for valid subdissectors in a TUserdata structure.
 *
 * @param L The Lua state to operate on.
 * @param ud The TUserdata structure containing information about subdissectors.
 * @param startoffset The starting offset for the subdissectors.
 */
static void push_offset_table (lua_State *L, TUserdata *ud, int startoffset) {
  int i, j;
  lua_newtable (L);
  for (i=1, j=1; i <= ALG_NSUB(ud); i++) {
    if (ALG_SUBVALID (ud,i)) {
      ALG_PUSHSTART (L, ud, startoffset, i);
      lua_rawseti (L, -2, j++);
      ALG_PUSHEND (L, ud, startoffset, i);
      lua_rawseti (L, -2, j++);
    }
    else {
      lua_pushboolean (L, 0);
      lua_rawseti (L, -2, j++);
      lua_pushboolean (L, 0);
      lua_rawseti (L, -2, j++);
    }
  }
}


/**
 * @brief Executes a generic find method based on the provided method type.
 *
 * This function is used to handle different find methods such as MATCH, FIND, and TFIND.
 * It checks if the start offset is within the valid range of the text length and then
 * calls the appropriate execution method based on the specified method.
 *
 * @param L The Lua state.
 * @param method The type of find method to execute (METHOD_EXEC, METHOD_TFIND, METHOD_MATCH, METHOD_FIND).
 * @return The number of values pushed onto the Lua stack.
 */
static int generic_find_method (lua_State *L, int method) {
  TUserdata *ud;
  TArgExec argE;
  int res;

  checkarg_find_method (L, &argE, &ud);
  if (argE.startoffset > (int)argE.textlen)
    return lua_pushnil(L), 1;

  res = findmatch_exec (ud, &argE);
  if (ALG_ISMATCH (res)) {
    switch (method) {
      case METHOD_EXEC:
        ALG_PUSHOFFSETS (L, ud, ALG_BASE(argE.startoffset), 0);
        push_offset_table (L, ud, ALG_BASE(argE.startoffset));
        DO_NAMED_SUBPATTERNS (L, ud, argE.text);
        return 3;
      case METHOD_TFIND:
        ALG_PUSHOFFSETS (L, ud, ALG_BASE(argE.startoffset), 0);
        push_substring_table (L, ud, argE.text);
        DO_NAMED_SUBPATTERNS (L, ud, argE.text);
        return 3;
      case METHOD_MATCH:
      case METHOD_FIND:
        return finish_generic_find (L, ud, &argE, method, res);
    }
    return 0;
  }
  else if (ALG_NOMATCH (res))
    return lua_pushnil (L), 1;
  else
    return generate_error(L, ud, res);
}


/**
 * @brief Lua function to perform a find operation.
 *
 * This function is used to invoke a generic find method in the Lua state.
 *
 * @param L The Lua state.
 * @return The result of the generic find method.
 */
static int algm_find (lua_State *L) {
  return generic_find_method (L, METHOD_FIND);
}

/**
 * @brief Executes a method based on the provided Lua state.
 *
 * This function is responsible for finding and executing a method using the generic_find_method function.
 *
 * @param L The Lua state to operate on.
 * @return The result of the method execution.
 */
static int algm_match (lua_State *L) {
  return generic_find_method (L, METHOD_MATCH);
}

/**
 * @brief Finds a method in the Lua state.
 *
 * @param L The Lua state to operate on.
 * @return The result of the method execution.
 */
static int algm_tfind (lua_State *L) {
  return generic_find_method (L, METHOD_TFIND);
}

/**
 * @brief Executes a method based on the provided Lua state.
 *
 * This function is responsible for finding and executing a method using the generic_find_method function.
 *
 * @param L The Lua state to operate on.
 * @return The result of the method execution.
 */
static int algm_exec (lua_State *L) {
  return generic_find_method (L, METHOD_EXEC);
}

/**
 * @brief Registers methods and functions for a Lua module.
 *
 * This function registers the specified methods and functions into a new Lua table,
 * which is then used as a metatable for the given module name. It handles compatibility
 * with different versions of Lua (5.1 and later).
 *
 * @param L The Lua state to operate on.
 * @param r_methods Pointer to an array of luaL_Reg structures containing method definitions.
 * @param r_functions Pointer to an array of luaL_Reg structures containing function definitions.
 * @param name The name of the module for which the methods and functions are being registered.
 */
static void alg_register (lua_State *L, const luaL_Reg *r_methods,
                          const luaL_Reg *r_functions, const char *name) {
  /* Create a new function environment to serve as a metatable for methods. */
#if LUA_VERSION_NUM == 501
  lua_newtable (L);
  lua_pushvalue (L, -1);
  lua_replace (L, LUA_ENVIRONINDEX);
  luaL_register (L, NULL, r_methods);
#else
  luaL_newmetatable(L, REX_TYPENAME);
  lua_pushvalue(L, -1);
  luaL_setfuncs (L, r_methods, 1);
#endif
  lua_pushvalue(L, -1); /* mt.__index = mt */
  lua_setfield(L, -2, "__index");

  /* Register functions. */
  lua_createtable(L, 0, 8);
#if LUA_VERSION_NUM == 501
  luaL_register (L, NULL, r_functions);
#else
  lua_pushvalue(L, -2);
  luaL_setfuncs (L, r_functions, 1);
#endif
#ifdef REX_CREATEGLOBALVAR
  lua_pushvalue(L, -1);
  lua_setglobal(L, REX_LIBNAME);
#endif
  lua_pushfstring (L, REX_VERSION" (for %s)", name);
  lua_setfield (L, -2, "_VERSION");
#ifndef REX_NOEMBEDDEDTEST
  lua_pushcfunction (L, newmembuffer);
  lua_setfield (L, -2, "_newmembuffer");
#endif
}
