#-----------------------------------------------------------------------------
# ply: yacc.py
#
# Author(s): David M. Beazley (dave@dabeaz.com)
#
# Copyright (C) 2001-2006, David M. Beazley
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
# 
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
# 
# See the file COPYING for a complete copy of the LGPL.
#
#
# This implements an LR parser that is constructed from grammar rules defined
# as Python functions. The grammer is specified by supplying the BNF inside
# Python documentation strings.  The inspiration for this technique was borrowed
# from John Aycock's Spark parsing system.  PLY might be viewed as cross between
# Spark and the GNU bison utility.
#
# The current implementation is only somewhat object-oriented. The
# LR parser itself is defined in terms of an object (which allows multiple
# parsers to co-exist).  However, most of the variables used during table
# construction are defined in terms of global variables.  Users shouldn't
# notice unless they are trying to define multiple parsers at the same
# time using threads (in which case they should have their head examined).
#
# This implementation supports both SLR and LALR(1) parsing.  LALR(1)
# support was originally implemented by Elias Ioup (ezioup@alumni.uchicago.edu),
# using the algorithm found in Aho, Sethi, and Ullman "Compilers: Principles,
# Techniques, and Tools" (The Dragon Book).  LALR(1) has since been replaced
# by the more efficient DeRemer and Pennello algorithm.
#
# :::::::: WARNING :::::::
#
# Construction of LR parsing tables is fairly complicated and expensive.
# To make this module run fast, a *LOT* of work has been put into
# optimization---often at the expensive of readability and what might
# consider to be good Python "coding style."   Modify the code at your
# own risk!
# ----------------------------------------------------------------------------

__version__ = "2.2"

#-----------------------------------------------------------------------------
#                     === User configurable parameters ===
#
# Change these to modify the default behavior of yacc (if you wish)
#-----------------------------------------------------------------------------

yaccdebug   = 1                # Debugging mode.  If set, yacc generates a
                               # a 'parser.out' file in the current directory

debug_file  = 'parser.out'     # Default name of the debugging file
tab_module  = 'parsetab'       # Default name of the table module
default_lr  = 'LALR'           # Default LR table generation method

error_count = 3                # Number of symbols that must be shifted to leave recovery mode

import re, types, sys, cStringIO, md5, os.path

# Exception raised for yacc-related errors
class YaccError(Exception):   pass

#-----------------------------------------------------------------------------
#                        ===  LR Parsing Engine ===
#
# The following classes are used for the LR parser itself.  These are not
# used during table construction and are independent of the actual LR
# table generation algorithm
#-----------------------------------------------------------------------------

# This class is used to hold non-terminal grammar symbols during parsing.
# It normally has the following attributes set:
#        .type       = Grammar symbol type
#        .value      = Symbol value
#        .lineno     = Starting line number
#        .endlineno  = Ending line number (optional, set automatically)
#        .lexpos     = Starting lex position
#        .endlexpos  = Ending lex position (optional, set automatically)

class YaccSymbol:
    def __str__(self):    return self.type
    def __repr__(self):   return str(self)

# This class is a wrapper around the objects actually passed to each
# grammar rule.   Index lookup and assignment actually assign the
# .value attribute of the underlying YaccSymbol object.
# The lineno() method returns the line number of a given
# item (or 0 if not defined).   The linespan() method returns
# a tuple of (startline,endline) representing the range of lines
# for a symbol.  The lexspan() method returns a tuple (lexpos,endlexpos)
# representing the range of positional information for a symbol.

class YaccProduction:
    def __init__(self,s,stack=None):
        self.slice = s
        self.pbstack = []
        self.stack = stack

    def __getitem__(self,n):
        if type(n) == types.IntType:
             if n >= 0: return self.slice[n].value
             else: return self.stack[n].value
        else:
             return [s.value for s in self.slice[n.start:n.stop:n.step]]

    def __setitem__(self,n,v):
        self.slice[n].value = v

    def __len__(self):
        return len(self.slice)
    
    def lineno(self,n):
        return getattr(self.slice[n],"lineno",0)

    def linespan(self,n):
        startline = getattr(self.slice[n],"lineno",0)
        endline = getattr(self.slice[n],"endlineno",startline)
        return startline,endline

    def lexpos(self,n):
        return getattr(self.slice[n],"lexpos",0)

    def lexspan(self,n):
        startpos = getattr(self.slice[n],"lexpos",0)
        endpos = getattr(self.slice[n],"endlexpos",startpos)
        return startpos,endpos

    def pushback(self,n):
        if n <= 0:
            raise ValueError, "Expected a positive value"
        if n > (len(self.slice)-1):
            raise ValueError, "Can't push %d tokens. Only %d are available." % (n,len(self.slice)-1)
        for i in range(0,n):
            self.pbstack.append(self.slice[-i-1])

# The LR Parsing engine.   This is defined as a class so that multiple parsers
# can exist in the same process.  A user never instantiates this directly.
# Instead, the global yacc() function should be used to create a suitable Parser
# object. 

class Parser:
    def __init__(self,magic=None):

        # This is a hack to keep users from trying to instantiate a Parser
        # object directly.

        if magic != "xyzzy":
            raise YaccError, "Can't instantiate Parser. Use yacc() instead."

        # Reset internal state
        self.productions = None          # List of productions
        self.errorfunc   = None          # Error handling function
        self.action      = { }           # LR Action table
        self.goto        = { }           # LR goto table
        self.require     = { }           # Attribute require table
        self.method      = "Unknown LR"  # Table construction method used

    def errok(self):
        self.errorcount = 0

    def restart(self):
        del self.statestack[:]
        del self.symstack[:]
        sym = YaccSymbol()
        sym.type = '$end'
        self.symstack.append(sym)
        self.statestack.append(0)
        
    def parse(self,input=None,lexer=None,debug=0):
        lookahead = None                 # Current lookahead symbol
        lookaheadstack = [ ]             # Stack of lookahead symbols
        actions = self.action            # Local reference to action table
        goto    = self.goto              # Local reference to goto table
        prod    = self.productions       # Local reference to production list
        pslice  = YaccProduction(None)   # Production object passed to grammar rules
        pslice.parser = self             # Parser object
        self.errorcount = 0              # Used during error recovery

        # If no lexer was given, we will try to use the lex module
        if not lexer:
            import lex
            lexer = lex.lexer

        pslice.lexer = lexer
        
        # If input was supplied, pass to lexer
        if input:
            lexer.input(input)

        # Tokenize function
        get_token = lexer.token

        statestack = [ ]                # Stack of parsing states
        self.statestack = statestack
        symstack   = [ ]                # Stack of grammar symbols
        self.symstack = symstack

        pslice.stack = symstack         # Put in the production
        errtoken   = None               # Err token

        # The start state is assumed to be (0,$end)
        statestack.append(0)
        sym = YaccSymbol()
        sym.type = '$end'
        symstack.append(sym)
        
        while 1:
            # Get the next symbol on the input.  If a lookahead symbol
            # is already set, we just use that. Otherwise, we'll pull
            # the next token off of the lookaheadstack or from the lexer
            if debug > 1:
                print 'state', statestack[-1]
            if not lookahead:
                if not lookaheadstack:
                    lookahead = get_token()     # Get the next token
                else:
                    lookahead = lookaheadstack.pop()
                if not lookahead:
                    lookahead = YaccSymbol()
                    lookahead.type = '$end'
            if debug:
                errorlead = ("%s . %s" % (" ".join([xx.type for xx in symstack][1:]), str(lookahead))).lstrip()

            # Check the action table
            s = statestack[-1]
            ltype = lookahead.type
            t = actions.get((s,ltype),None)

            if debug > 1:
                print 'action', t
            if t is not None:
                if t > 0:
                    # shift a symbol on the stack
                    if ltype == '$end':
                        # Error, end of input
                        sys.stderr.write("yacc: Parse error. EOF\n")
                        return
                    statestack.append(t)
                    if debug > 1:
                        sys.stderr.write("%-60s shift state %s\n" % (errorlead, t))
                    symstack.append(lookahead)
                    lookahead = None

                    # Decrease error count on successful shift
                    if self.errorcount > 0:
                        self.errorcount -= 1
                        
                    continue
                
                if t < 0:
                    # reduce a symbol on the stack, emit a production
                    p = prod[-t]
                    pname = p.name
                    plen  = p.len

                    # Get production function
                    sym = YaccSymbol()
                    sym.type = pname       # Production name
                    sym.value = None
                    if debug > 1:
                        sys.stderr.write("%-60s reduce %d\n" % (errorlead, -t))

                    if plen:
                        targ = symstack[-plen-1:]
                        targ[0] = sym
                        try:
                            sym.lineno = targ[1].lineno
                            sym.endlineno = getattr(targ[-1],"endlineno",targ[-1].lineno)
                            sym.lexpos = targ[1].lexpos
                            sym.endlexpos = getattr(targ[-1],"endlexpos",targ[-1].lexpos)
                        except AttributeError:
                            sym.lineno = 0
                        del symstack[-plen:]
                        del statestack[-plen:]
                    else:
                        sym.lineno = 0
                        targ = [ sym ]
                    pslice.slice = targ
                    pslice.pbstack = []
                    # Call the grammar rule with our special slice object
                    p.func(pslice)

                    # If there was a pushback, put that on the stack
                    if pslice.pbstack:
                        lookaheadstack.append(lookahead)
                        for _t in pslice.pbstack:
                            lookaheadstack.append(_t)
                        lookahead = None

                    symstack.append(sym)
                    statestack.append(goto[statestack[-1],pname])
                    continue

                if t == 0:
                    n = symstack[-1]
                    return getattr(n,"value",None)
                    sys.stderr.write(errorlead, "\n")

            if t == None:
                if debug:
                    sys.stderr.write(errorlead + "\n")
                # We have some kind of parsing error here.  To handle
                # this, we are going to push the current token onto
                # the tokenstack and replace it with an 'error' token.
                # If there are any synchronization rules, they may
                # catch it.
                #
                # In addition to pushing the error token, we call call
                # the user defined p_error() function if this is the
                # first syntax error.  This function is only called if
                # errorcount == 0.
                if not self.errorcount:
                    self.errorcount = error_count
                    errtoken = lookahead
                    if errtoken.type == '$end':
                        errtoken = None               # End of file!
                    if self.errorfunc:
                        global errok,token,restart
                        errok = self.errok        # Set some special functions available in error recovery
                        token = get_token
                        restart = self.restart
                        tok = self.errorfunc(errtoken)
                        del errok, token, restart   # Delete special functions
                        
                        if not self.errorcount:
                            # User must have done some kind of panic
                            # mode recovery on their own.  The
                            # returned token is the next lookahead
                            lookahead = tok
                            errtoken = None
                            continue
                    else:
                        if errtoken:
                            if hasattr(errtoken,"lineno"): lineno = lookahead.lineno
                            else: lineno = 0
                            if lineno:
                                sys.stderr.write("yacc: Syntax error at line %d, token=%s\n" % (lineno, errtoken.type))
                            else:
                                sys.stderr.write("yacc: Syntax error, token=%s" % errtoken.type)
                        else:
                            sys.stderr.write("yacc: Parse error in input. EOF\n")
                            return

                else:
                    self.errorcount = error_count
                
                # case 1:  the statestack only has 1 entry on it.  If we're in this state, the
                # entire parse has been rolled back and we're completely hosed.   The token is
                # discarded and we just keep going.

                if len(statestack) <= 1 and lookahead.type != '$end':
                    lookahead = None
                    errtoken = None
                    # Nuke the pushback stack
                    del lookaheadstack[:]
                    continue

                # case 2: the statestack has a couple of entries on it, but we're
                # at the end of the file. nuke the top entry and generate an error token

                # Start nuking entries on the stack
                if lookahead.type == '$end':
                    # Whoa. We're really hosed here. Bail out
                    return 

                if lookahead.type != 'error':
                    sym = symstack[-1]
                    if sym.type == 'error':
                        # Hmmm. Error is on top of stack, we'll just nuke input
                        # symbol and continue
                        lookahead = None
                        continue
                    t = YaccSymbol()
                    t.type = 'error'
                    if hasattr(lookahead,"lineno"):
                        t.lineno = lookahead.lineno
                    t.value = lookahead
                    lookaheadstack.append(lookahead)
                    lookahead = t
                else:
                    symstack.pop()
                    statestack.pop()

                continue

            # Call an error function here
            raise RuntimeError, "yacc: internal parser error!!!\n"

# -----------------------------------------------------------------------------
#                          === Parser Construction ===
#
# The following functions and variables are used to implement the yacc() function
# itself.   This is pretty hairy stuff involving lots of error checking,
# construction of LR items, kernels, and so forth.   Although a lot of
# this work is done using global variables, the resulting Parser object
# is completely self contained--meaning that it is safe to repeatedly
# call yacc() with different grammars in the same application.
# -----------------------------------------------------------------------------
        
# -----------------------------------------------------------------------------
# validate_file()
#
# This function checks to see if there are duplicated p_rulename() functions
# in the parser module file.  Without this function, it is really easy for
# users to make mistakes by cutting and pasting code fragments (and it's a real
# bugger to try and figure out why the resulting parser doesn't work).  Therefore,
# we just do a little regular expression pattern matching of def statements
# to try and detect duplicates.
# -----------------------------------------------------------------------------

def validate_file(filename):
    base,ext = os.path.splitext(filename)
    if ext != '.py': return 1          # No idea. Assume it's okay.

    try:
        f = open(filename)
        lines = f.readlines()
        f.close()
    except IOError:
        return 1                       # Oh well

    # Match def p_funcname(
    fre = re.compile(r'\s*def\s+(p_[a-zA-Z_0-9]*)\(')
    counthash = { }
    linen = 1
    noerror = 1
    for l in lines:
        m = fre.match(l)
        if m:
            name = m.group(1)
            prev = counthash.get(name)
            if not prev:
                counthash[name] = linen
            else:
                sys.stderr.write("%s:%d: Function %s redefined. Previously defined on line %d\n" % (filename,linen,name,prev))
                noerror = 0
        linen += 1
    return noerror

# This function looks for functions that might be grammar rules, but which don't have the proper p_suffix.
def validate_dict(d):
    for n,v in d.items(): 
        if n[0:2] == 'p_' and type(v) in (types.FunctionType, types.MethodType): continue
        if n[0:2] == 't_': continue

        if n[0:2] == 'p_':
            sys.stderr.write("yacc: Warning. '%s' not defined as a function\n" % n)
        if 1 and isinstance(v,types.FunctionType) and v.func_code.co_argcount == 1:
            try:
                doc = v.__doc__.split(" ")
                if doc[1] == ':':
                    sys.stderr.write("%s:%d: Warning. Possible grammar rule '%s' defined without p_ prefix.\n" % (v.func_code.co_filename, v.func_code.co_firstlineno,n))
            except StandardError:
                pass

# -----------------------------------------------------------------------------
#                           === GRAMMAR FUNCTIONS ===
#
# The following global variables and functions are used to store, manipulate,
# and verify the grammar rules specified by the user.
# -----------------------------------------------------------------------------

# Initialize all of the global variables used during grammar construction
def initialize_vars():
    global Productions, Prodnames, Prodmap, Terminals 
    global Nonterminals, First, Follow, Precedence, LRitems
    global Errorfunc, Signature, Requires

    Productions  = [None]  # A list of all of the productions.  The first
                           # entry is always reserved for the purpose of
                           # building an augmented grammar
                        
    Prodnames    = { }     # A dictionary mapping the names of nonterminals to a list of all
                           # productions of that nonterminal.
                        
    Prodmap      = { }     # A dictionary that is only used to detect duplicate
                           # productions.

    Terminals    = { }     # A dictionary mapping the names of terminal symbols to a
                           # list of the rules where they are used.

    Nonterminals = { }     # A dictionary mapping names of nonterminals to a list
                           # of rule numbers where they are used.

    First        = { }     # A dictionary of precomputed FIRST(x) symbols
    
    Follow       = { }     # A dictionary of precomputed FOLLOW(x) symbols

    Precedence   = { }     # Precedence rules for each terminal. Contains tuples of the
                           # form ('right',level) or ('nonassoc', level) or ('left',level)

    LRitems      = [ ]     # A list of all LR items for the grammar.  These are the
                           # productions with the "dot" like E -> E . PLUS E

    Errorfunc    = None    # User defined error handler

    Signature    = md5.new()   # Digital signature of the grammar rules, precedence
                               # and other information.  Used to determined when a
                               # parsing table needs to be regenerated.

    Requires     = { }     # Requires list

    # File objects used when creating the parser.out debugging file
    global _vf, _vfc
    _vf           = cStringIO.StringIO()
    _vfc          = cStringIO.StringIO()

# -----------------------------------------------------------------------------
# class Production:
#
# This class stores the raw information about a single production or grammar rule.
# It has a few required attributes:
#
#       name     - Name of the production (nonterminal)
#       prod     - A list of symbols making up its production
#       number   - Production number.
#
# In addition, a few additional attributes are used to help with debugging or
# optimization of table generation.
#
#       file     - File where production action is defined.
#       lineno   - Line number where action is defined
#       func     - Action function
#       prec     - Precedence level
#       lr_next  - Next LR item. Example, if we are ' E -> E . PLUS E'
#                  then lr_next refers to 'E -> E PLUS . E'   
#       lr_index - LR item index (location of the ".") in the prod list.
#       lookaheads - LALR lookahead symbols for this item
#       len      - Length of the production (number of symbols on right hand side)
# -----------------------------------------------------------------------------

class Production:
    def __init__(self,**kw):
        for k,v in kw.items():
            setattr(self,k,v)
        self.lr_index = -1
        self.lr0_added = 0    # Flag indicating whether or not added to LR0 closure
        self.lr1_added = 0    # Flag indicating whether or not added to LR1
        self.usyms = [ ]
        self.lookaheads = { }
        self.lk_added = { }
        self.setnumbers = [ ]
        
    def __str__(self):
        if self.prod:
            s = "%s -> %s" % (self.name," ".join(self.prod))
        else:
            s = "%s -> <empty>" % self.name
        return s

    def __repr__(self):
        return str(self)

    # Compute lr_items from the production
    def lr_item(self,n):
        if n > len(self.prod): return None
        p = Production()
        p.name = self.name
        p.prod = list(self.prod)
        p.number = self.number
        p.lr_index = n
        p.lookaheads = { }
        p.setnumbers = self.setnumbers
        p.prod.insert(n,".")
        p.prod = tuple(p.prod)
        p.len = len(p.prod)
        p.usyms = self.usyms

        # Precompute list of productions immediately following
        try:
            p.lrafter = Prodnames[p.prod[n+1]]
        except (IndexError,KeyError),e:
            p.lrafter = []
        try:
            p.lrbefore = p.prod[n-1]
        except IndexError:
            p.lrbefore = None

        return p

class MiniProduction:
    pass

# regex matching identifiers
_is_identifier = re.compile(r'^[a-zA-Z0-9_-]+$')

# -----------------------------------------------------------------------------
# add_production()
#
# Given an action function, this function assembles a production rule.
# The production rule is assumed to be found in the function's docstring.
# This rule has the general syntax:
#
#              name1 ::= production1
#                     |  production2
#                     |  production3
#                    ...
#                     |  productionn
#              name2 ::= production1
#                     |  production2
#                    ... 
# -----------------------------------------------------------------------------

def add_production(f,file,line,prodname,syms):
    
    if Terminals.has_key(prodname):
        sys.stderr.write("%s:%d: Illegal rule name '%s'. Already defined as a token.\n" % (file,line,prodname))
        return -1
    if prodname == 'error':
        sys.stderr.write("%s:%d: Illegal rule name '%s'. error is a reserved word.\n" % (file,line,prodname))
        return -1
                
    if not _is_identifier.match(prodname):
        sys.stderr.write("%s:%d: Illegal rule name '%s'\n" % (file,line,prodname))
        return -1

    for x in range(len(syms)):
        s = syms[x]
        if s[0] in "'\"":
             try:
                 c = eval(s)
                 if (len(c) > 1):
                      sys.stderr.write("%s:%d: Literal token %s in rule '%s' may only be a single character\n" % (file,line,s, prodname)) 
                      return -1
                 if not Terminals.has_key(c):
                      Terminals[c] = []
                 syms[x] = c
                 continue
             except SyntaxError:
                 pass
        if not _is_identifier.match(s) and s != '%prec':
            sys.stderr.write("%s:%d: Illegal name '%s' in rule '%s'\n" % (file,line,s, prodname))
            return -1

    # See if the rule is already in the rulemap
    map = "%s -> %s" % (prodname,syms)
    if Prodmap.has_key(map):
        m = Prodmap[map]
        sys.stderr.write("%s:%d: Duplicate rule %s.\n" % (file,line, m))
        sys.stderr.write("%s:%d: Previous definition at %s:%d\n" % (file,line, m.file, m.line))
        return -1

    p = Production()
    p.name = prodname
    p.prod = syms
    p.file = file
    p.line = line
    p.func = f
    p.number = len(Productions)

            
    Productions.append(p)
    Prodmap[map] = p
    if not Nonterminals.has_key(prodname):
        Nonterminals[prodname] = [ ]
    
    # Add all terminals to Terminals
    i = 0
    while i < len(p.prod):
        t = p.prod[i]
        if t == '%prec':
            try:
                precname = p.prod[i+1]
            except IndexError:
                sys.stderr.write("%s:%d: Syntax error. Nothing follows %%prec.\n" % (p.file,p.line))
                return -1

            prec = Precedence.get(precname,None)
            if not prec:
                sys.stderr.write("%s:%d: Nothing known about the precedence of '%s'\n" % (p.file,p.line,precname))
                return -1
            else:
                p.prec = prec
            del p.prod[i]
            del p.prod[i]
            continue

        if Terminals.has_key(t):
            Terminals[t].append(p.number)
            # Is a terminal.  We'll assign a precedence to p based on this
            if not hasattr(p,"prec"):
                p.prec = Precedence.get(t,('right',0))
        else:
            if not Nonterminals.has_key(t):
                Nonterminals[t] = [ ]
            Nonterminals[t].append(p.number)
        i += 1

    if not hasattr(p,"prec"):
        p.prec = ('right',0)
        
    # Set final length of productions
    p.len  = len(p.prod)
    p.prod = tuple(p.prod)

    # Calculate unique syms in the production
    p.usyms = [ ]
    for s in p.prod:
        if s not in p.usyms:
            p.usyms.append(s)
    
    # Add to the global productions list
    try:
        Prodnames[p.name].append(p)
    except KeyError:
        Prodnames[p.name] = [ p ]
    return 0

# Given a raw rule function, this function rips out its doc string
# and adds rules to the grammar

def add_function(f):
    line = f.func_code.co_firstlineno
    file = f.func_code.co_filename
    error = 0

    if isinstance(f,types.MethodType):
        reqdargs = 2
    else:
        reqdargs = 1
        
    if f.func_code.co_argcount > reqdargs:
        sys.stderr.write("%s:%d: Rule '%s' has too many arguments.\n" % (file,line,f.__name__))
        return -1

    if f.func_code.co_argcount < reqdargs:
        sys.stderr.write("%s:%d: Rule '%s' requires an argument.\n" % (file,line,f.__name__))
        return -1
          
    if f.__doc__:
        # Split the doc string into lines
        pstrings = f.__doc__.splitlines()
        lastp = None
        dline = line
        for ps in pstrings:
            dline += 1
            p = ps.split()
            if not p: continue
            try:
                if p[0] == '|':
                    # This is a continuation of a previous rule
                    if not lastp:
                        sys.stderr.write("%s:%d: Misplaced '|'.\n" % (file,dline))
                        return -1
                    prodname = lastp
                    if len(p) > 1:
                        syms = p[1:]
                    else:
                        syms = [ ]
                else:
                    prodname = p[0]
                    lastp = prodname
                    assign = p[1]
                    if len(p) > 2:
                        syms = p[2:]
                    else:
                        syms = [ ]
                    if assign != ':' and assign != '::=':
                        sys.stderr.write("%s:%d: Syntax error. Expected ':'\n" % (file,dline))
                        return -1
                         
 
                e = add_production(f,file,dline,prodname,syms)
                error += e

                
            except StandardError:
                sys.stderr.write("%s:%d: Syntax error in rule '%s'\n" % (file,dline,ps))
                error -= 1
    else:
        sys.stderr.write("%s:%d: No documentation string specified in function '%s'\n" % (file,line,f.__name__))
    return error


# Cycle checking code (Michael Dyck)

def compute_reachable():
    '''
    Find each symbol that can be reached from the start symbol.
    Print a warning for any nonterminals that can't be reached.
    (Unused terminals have already had their warning.)
    '''
    Reachable = { }
    for s in Terminals.keys() + Nonterminals.keys():
        Reachable[s] = 0

    mark_reachable_from( Productions[0].prod[0], Reachable )

    for s in Nonterminals.keys():
        if not Reachable[s]:
            sys.stderr.write("yacc: Symbol '%s' is unreachable.\n" % s)

def mark_reachable_from(s, Reachable):
    '''
    Mark all symbols that are reachable from symbol s.
    '''
    if Reachable[s]:
        # We've already reached symbol s.
        return
    Reachable[s] = 1
    for p in Prodnames.get(s,[]):
        for r in p.prod:
            mark_reachable_from(r, Reachable)

# -----------------------------------------------------------------------------
# compute_terminates()
#
# This function looks at the various parsing rules and tries to detect
# infinite recursion cycles (grammar rules where there is no possible way
# to derive a string of only terminals).
# -----------------------------------------------------------------------------
def compute_terminates():
    '''
    Raise an error for any symbols that don't terminate.
    '''
    Terminates = {}

    # Terminals:
    for t in Terminals.keys():
        Terminates[t] = 1

    Terminates['$end'] = 1

    # Nonterminals:

    # Initialize to false:
    for n in Nonterminals.keys():
        Terminates[n] = 0

    # Then propagate termination until no change:
    while 1:
        some_change = 0
        for (n,pl) in Prodnames.items():
            # Nonterminal n terminates iff any of its productions terminates.
            for p in pl:
                # Production p terminates iff all of its rhs symbols terminate.
                for s in p.prod:
                    if not Terminates[s]:
                        # The symbol s does not terminate,
                        # so production p does not terminate.
                        p_terminates = 0
                        break
                else:
                    # didn't break from the loop,
                    # so every symbol s terminates
                    # so production p terminates.
                    p_terminates = 1

                if p_terminates:
                    # symbol n terminates!
                    if not Terminates[n]:
                        Terminates[n] = 1
                        some_change = 1
                    # Don't need to consider any more productions for this n.
                    break

        if not some_change:
            break

    some_error = 0
    for (s,terminates) in Terminates.items():
        if not terminates:
            if not Prodnames.has_key(s) and not Terminals.has_key(s) and s != 'error':
                # s is used-but-not-defined, and we've already warned of that,
                # so it would be overkill to say that it's also non-terminating.
                pass
            else:
                sys.stderr.write("yacc: Infinite recursion detected for symbol '%s'.\n" % s)
                some_error = 1

    return some_error

# -----------------------------------------------------------------------------
# verify_productions()
#
# This function examines all of the supplied rules to see if they seem valid.
# -----------------------------------------------------------------------------
def verify_productions(cycle_check=1):
    error = 0
    for p in Productions:
        if not p: continue

        for s in p.prod:
            if not Prodnames.has_key(s) and not Terminals.has_key(s) and s != 'error':
                sys.stderr.write("%s:%d: Symbol '%s' used, but not defined as a token or a rule.\n" % (p.file,p.line,s))
                error = 1
                continue

    unused_tok = 0 
    # Now verify all of the tokens
    if yaccdebug:
        _vf.write("Unused terminals:\n\n")
    for s,v in Terminals.items():
        if s != 'error' and not v:
            sys.stderr.write("yacc: Warning. Token '%s' defined, but not used.\n" % s)
            if yaccdebug: _vf.write("   %s\n"% s)
            unused_tok += 1

    # Print out all of the productions
    if yaccdebug:
        _vf.write("\nGrammar\n\n")
        for i in range(1,len(Productions)):
            _vf.write("Rule %-5d %s\n" % (i, Productions[i]))
        
    unused_prod = 0
    # Verify the use of all productions
    for s,v in Nonterminals.items():
        if not v:
            p = Prodnames[s][0]
            sys.stderr.write("%s:%d: Warning. Rule '%s' defined, but not used.\n" % (p.file,p.line, s))
            unused_prod += 1

    
    if unused_tok == 1:
        sys.stderr.write("yacc: Warning. There is 1 unused token.\n")
    if unused_tok > 1:
        sys.stderr.write("yacc: Warning. There are %d unused tokens.\n" % unused_tok)

    if unused_prod == 1:
        sys.stderr.write("yacc: Warning. There is 1 unused rule.\n")
    if unused_prod > 1:
        sys.stderr.write("yacc: Warning. There are %d unused rules.\n" % unused_prod)

    if yaccdebug:
        _vf.write("\nTerminals, with rules where they appear\n\n")
        ks = Terminals.keys()
        ks.sort()
        for k in ks:
            _vf.write("%-20s : %s\n" % (k, " ".join([str(s) for s in Terminals[k]])))
        _vf.write("\nNonterminals, with rules where they appear\n\n")
        ks = Nonterminals.keys()
        ks.sort()
        for k in ks:
            _vf.write("%-20s : %s\n" % (k, " ".join([str(s) for s in Nonterminals[k]])))

    if (cycle_check):
        compute_reachable()
        error += compute_terminates()
#        error += check_cycles()
    return error

# -----------------------------------------------------------------------------
# build_lritems()
#
# This function walks the list of productions and builds a complete set of the
# LR items.  The LR items are stored in two ways:  First, they are uniquely
# numbered and placed in the list _lritems.  Second, a linked list of LR items
# is built for each production.  For example:
#
#   E -> E PLUS E
#
# Creates the list
#
#  [E -> . E PLUS E, E -> E . PLUS E, E -> E PLUS . E, E -> E PLUS E . ] 
# -----------------------------------------------------------------------------

def build_lritems():
    for p in Productions:
        lastlri = p
        lri = p.lr_item(0)
        i = 0
        while 1:
            lri = p.lr_item(i)
            lastlri.lr_next = lri
            if not lri: break
            lri.lr_num = len(LRitems)
            LRitems.append(lri)
            lastlri = lri
            i += 1

    # In order for the rest of the parser generator to work, we need to
    # guarantee that no more lritems are generated.  Therefore, we nuke
    # the p.lr_item method.  (Only used in debugging)
    # Production.lr_item = None

# -----------------------------------------------------------------------------
# add_precedence()
#
# Given a list of precedence rules, add to the precedence table.
# -----------------------------------------------------------------------------

def add_precedence(plist):
    plevel = 0
    error = 0
    for p in plist:
        plevel += 1
        try:
            prec = p[0]
            terms = p[1:]
            if prec != 'left' and prec != 'right' and prec != 'nonassoc':
                sys.stderr.write("yacc: Invalid precedence '%s'\n" % prec)
                return -1
            for t in terms:
                if Precedence.has_key(t):
                    sys.stderr.write("yacc: Precedence already specified for terminal '%s'\n" % t)
                    error += 1
                    continue
                Precedence[t] = (prec,plevel)
        except:
            sys.stderr.write("yacc: Invalid precedence table.\n")
            error += 1

    return error

# -----------------------------------------------------------------------------
# augment_grammar()
#
# Compute the augmented grammar.  This is just a rule S' -> start where start
# is the starting symbol.
# -----------------------------------------------------------------------------

def augment_grammar(start=None):
    if not start:
        start = Productions[1].name
    Productions[0] = Production(name="S'",prod=[start],number=0,len=1,prec=('right',0),func=None)
    Productions[0].usyms = [ start ]
    Nonterminals[start].append(0)


# -------------------------------------------------------------------------
# first()
#
# Compute the value of FIRST1(beta) where beta is a tuple of symbols.
#
# During execution of compute_first1, the result may be incomplete.
# Afterward (e.g., when called from compute_follow()), it will be complete.
# -------------------------------------------------------------------------
def first(beta):

    # We are computing First(x1,x2,x3,...,xn)
    result = [ ]
    for x in beta:
        x_produces_empty = 0

        # Add all the non-<empty> symbols of First[x] to the result.
        for f in First[x]:
            if f == '<empty>':
                x_produces_empty = 1
            else:
                if f not in result: result.append(f)

        if x_produces_empty:
            # We have to consider the next x in beta,
            # i.e. stay in the loop.
            pass
        else:
            # We don't have to consider any further symbols in beta.
            break
    else:
        # There was no 'break' from the loop,
        # so x_produces_empty was true for all x in beta,
        # so beta produces empty as well.
        result.append('<empty>')

    return result


# FOLLOW(x)
# Given a non-terminal.  This function computes the set of all symbols
# that might follow it.  Dragon book, p. 189.

def compute_follow(start=None):
    # Add '$end' to the follow list of the start symbol
    for k in Nonterminals.keys():
        Follow[k] = [ ]

    if not start:
        start = Productions[1].name
        
    Follow[start] = [ '$end' ]
        
    while 1:
        didadd = 0
        for p in Productions[1:]:
            # Here is the production set
            for i in range(len(p.prod)):
                B = p.prod[i]
                if Nonterminals.has_key(B):
                    # Okay. We got a non-terminal in a production
                    fst = first(p.prod[i+1:])
                    hasempty = 0
                    for f in fst:
                        if f != '<empty>' and f not in Follow[B]:
                            Follow[B].append(f)
                            didadd = 1
                        if f == '<empty>':
                            hasempty = 1
                    if hasempty or i == (len(p.prod)-1):
                        # Add elements of follow(a) to follow(b)
                        for f in Follow[p.name]:
                            if f not in Follow[B]:
                                Follow[B].append(f)
                                didadd = 1
        if not didadd: break

    if 0 and yaccdebug:
        _vf.write('\nFollow:\n')
        for k in Nonterminals.keys():
            _vf.write("%-20s : %s\n" % (k, " ".join([str(s) for s in Follow[k]])))

# -------------------------------------------------------------------------
# compute_first1()
#
# Compute the value of FIRST1(X) for all symbols
# -------------------------------------------------------------------------
def compute_first1():

    # Terminals:
    for t in Terminals.keys():
        First[t] = [t]

    First['$end'] = ['$end']
    First['#'] = ['#'] # what's this for?

    # Nonterminals:

    # Initialize to the empty set:
    for n in Nonterminals.keys():
        First[n] = []

    # Then propagate symbols until no change:
    while 1:
        some_change = 0
        for n in Nonterminals.keys():
            for p in Prodnames[n]:
                for f in first(p.prod):
                    if f not in First[n]:
                        First[n].append( f )
                        some_change = 1
        if not some_change:
            break

    if 0 and yaccdebug:
        _vf.write('\nFirst:\n')
        for k in Nonterminals.keys():
            _vf.write("%-20s : %s\n" %
                (k, " ".join([str(s) for s in First[k]])))

# -----------------------------------------------------------------------------
#                           === SLR Generation ===
#
# The following functions are used to construct SLR (Simple LR) parsing tables
# as described on p.221-229 of the dragon book.
# -----------------------------------------------------------------------------

# Global variables for the LR parsing engine
def lr_init_vars():
    global _lr_action, _lr_goto, _lr_method
    global _lr_goto_cache, _lr0_cidhash
    
    _lr_action       = { }        # Action table
    _lr_goto         = { }        # Goto table
    _lr_method       = "Unknown"  # LR method used
    _lr_goto_cache   = { }
    _lr0_cidhash     = { }


# Compute the LR(0) closure operation on I, where I is a set of LR(0) items.
# prodlist is a list of productions.

_add_count = 0       # Counter used to detect cycles

def lr0_closure(I):
    global _add_count
    
    _add_count += 1
    prodlist = Productions
    
    # Add everything in I to J        
    J = I[:]
    didadd = 1
    while didadd:
        didadd = 0
        for j in J:
            for x in j.lrafter:
                if x.lr0_added == _add_count: continue
                # Add B --> .G to J
                J.append(x.lr_next)
                x.lr0_added = _add_count
                didadd = 1
               
    return J

# Compute the LR(0) goto function goto(I,X) where I is a set
# of LR(0) items and X is a grammar symbol.   This function is written
# in a way that guarantees uniqueness of the generated goto sets
# (i.e. the same goto set will never be returned as two different Python
# objects).  With uniqueness, we can later do fast set comparisons using
# id(obj) instead of element-wise comparison.

def lr0_goto(I,x):
    # First we look for a previously cached entry
    g = _lr_goto_cache.get((id(I),x),None)
    if g: return g

    # Now we generate the goto set in a way that guarantees uniqueness
    # of the result
    
    s = _lr_goto_cache.get(x,None)
    if not s:
        s = { }
        _lr_goto_cache[x] = s

    gs = [ ]
    for p in I:
        n = p.lr_next
        if n and n.lrbefore == x:
            s1 = s.get(id(n),None)
            if not s1:
                s1 = { }
                s[id(n)] = s1
            gs.append(n)
            s = s1
    g = s.get('$end',None)
    if not g:
        if gs:
            g = lr0_closure(gs)
            s['$end'] = g
        else:
            s['$end'] = gs
    _lr_goto_cache[(id(I),x)] = g
    return g

_lr0_cidhash = { }

# Compute the LR(0) sets of item function
def lr0_items():
    
    C = [ lr0_closure([Productions[0].lr_next]) ]
    i = 0
    for I in C:
        _lr0_cidhash[id(I)] = i
        i += 1

    # Loop over the items in C and each grammar symbols
    i = 0
    while i < len(C):
        I = C[i]
        i += 1

        # Collect all of the symbols that could possibly be in the goto(I,X) sets
        asyms = { }
        for ii in I:
            for s in ii.usyms:
                asyms[s] = None

        for x in asyms.keys():
            g = lr0_goto(I,x)
            if not g:  continue
            if _lr0_cidhash.has_key(id(g)): continue
            _lr0_cidhash[id(g)] = len(C)            
            C.append(g)
            
    return C

# -----------------------------------------------------------------------------
#                       ==== LALR(1) Parsing ====
#
# LALR(1) parsing is almost exactly the same as SLR except that instead of
# relying upon Follow() sets when performing reductions, a more selective
# lookahead set that incorporates the state of the LR(0) machine is utilized.
# Thus, we mainly just have to focus on calculating the lookahead sets.
#
# The method used here is due to DeRemer and Pennelo (1982).
#
# DeRemer, F. L., and T. J. Pennelo: "Efficient Computation of LALR(1)
#     Lookahead Sets", ACM Transactions on Programming Languages and Systems,
#     Vol. 4, No. 4, Oct. 1982, pp. 615-649
#
# Further details can also be found in:
#
#  J. Tremblay and P. Sorenson, "The Theory and Practice of Compiler Writing",
#      McGraw-Hill Book Company, (1985).
#
# Note:  This implementation is a complete replacement of the LALR(1) 
#        implementation in PLY-1.x releases.   That version was based on
#        a less efficient algorithm and it had bugs in its implementation.
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# compute_nullable_nonterminals()
#
# Creates a dictionary containing all of the non-terminals that might produce
# an empty production.   
# -----------------------------------------------------------------------------

def compute_nullable_nonterminals():
    nullable = {}
    num_nullable = 0
    while 1:
       for p in Productions[1:]:
           if p.len == 0:
                nullable[p.name] = 1
                continue
           for t in p.prod:
                if not nullable.has_key(t): break
           else:
                nullable[p.name] = 1
       if len(nullable) == num_nullable: break
       num_nullable = len(nullable)
    return nullable

# -----------------------------------------------------------------------------
# find_nonterminal_trans(C)
#
# Given a set of LR(0) items, this functions finds all of the non-terminal
# transitions.    These are transitions in which a dot appears immediately before
# a non-terminal.   Returns a list of tuples of the form (state,N) where state
# is the state number and N is the nonterminal symbol.
#
# The input C is the set of LR(0) items.
# -----------------------------------------------------------------------------

def find_nonterminal_transitions(C):
     trans = []
     for state in range(len(C)):
         for p in C[state]:
             if p.lr_index < p.len - 1:
                  t = (state,p.prod[p.lr_index+1])
                  if Nonterminals.has_key(t[1]):
                        if t not in trans: trans.append(t)
         state = state + 1
     return trans

# -----------------------------------------------------------------------------
# dr_relation()
#
# Computes the DR(p,A) relationships for non-terminal transitions.  The input
# is a tuple (state,N) where state is a number and N is a nonterminal symbol.
#
# Returns a list of terminals.
# -----------------------------------------------------------------------------

def dr_relation(C,trans,nullable):
    dr_set = { }
    state,N = trans
    terms = []

    g = lr0_goto(C[state],N)
    for p in g:
       if p.lr_index < p.len - 1:
           a = p.prod[p.lr_index+1]
           if Terminals.has_key(a):
               if a not in terms: terms.append(a)

    # This extra bit is to handle the start state
    if state == 0 and N == Productions[0].prod[0]:
       terms.append('$end')
 
    return terms

# -----------------------------------------------------------------------------
# reads_relation()
#
# Computes the READS() relation (p,A) READS (t,C).
# -----------------------------------------------------------------------------

def reads_relation(C, trans, empty):
    # Look for empty transitions
    rel = []
    state, N = trans

    g = lr0_goto(C[state],N)
    j = _lr0_cidhash.get(id(g),-1)
    for p in g:
        if p.lr_index < p.len - 1:
             a = p.prod[p.lr_index + 1]
             if empty.has_key(a):
                  rel.append((j,a))

    return rel

# -----------------------------------------------------------------------------
# compute_lookback_includes()
#
# Determines the lookback and includes relations
#
# LOOKBACK:
# 
# This relation is determined by running the LR(0) state machine forward.
# For example, starting with a production "N : . A B C", we run it forward
# to obtain "N : A B C ."   We then build a relationship between this final
# state and the starting state.   These relationships are stored in a dictionary
# lookdict.   
#
# INCLUDES:
#
# Computes the INCLUDE() relation (p,A) INCLUDES (p',B).   
#
# This relation is used to determine non-terminal transitions that occur
# inside of other non-terminal transition states.   (p,A) INCLUDES (p', B)
# if the following holds:
#
#       B -> LAT, where T -> epsilon and p' -L-> p 
#
# L is essentially a prefix (which may be empty), T is a suffix that must be
# able to derive an empty string.  State p' must lead to state p with the string L.
# 
# -----------------------------------------------------------------------------

def compute_lookback_includes(C,trans,nullable):
    
    lookdict = {}          # Dictionary of lookback relations
    includedict = {}       # Dictionary of include relations

    # Make a dictionary of non-terminal transitions
    dtrans = {}
    for t in trans:
        dtrans[t] = 1
    
    # Loop over all transitions and compute lookbacks and includes
    for state,N in trans:
        lookb = []
        includes = []
        for p in C[state]:
            if p.name != N: continue
        
            # Okay, we have a name match.  We now follow the production all the way
            # through the state machine until we get the . on the right hand side

            lr_index = p.lr_index
            j = state
            while lr_index < p.len - 1:
                 lr_index = lr_index + 1
                 t = p.prod[lr_index]

                 # Check to see if this symbol and state are a non-terminal transition
                 if dtrans.has_key((j,t)):
                       # Yes.  Okay, there is some chance that this is an includes relation
                       # the only way to know for certain is whether the rest of the 
                       # production derives empty

                       li = lr_index + 1
                       while li < p.len:
                            if Terminals.has_key(p.prod[li]): break      # No forget it
                            if not nullable.has_key(p.prod[li]): break
                            li = li + 1
                       else:
                            # Appears to be a relation between (j,t) and (state,N)
                            includes.append((j,t))

                 g = lr0_goto(C[j],t)               # Go to next set             
                 j = _lr0_cidhash.get(id(g),-1)     # Go to next state
             
            # When we get here, j is the final state, now we have to locate the production
            for r in C[j]:
                 if r.name != p.name: continue
                 if r.len != p.len:   continue
                 i = 0
                 # This look is comparing a production ". A B C" with "A B C ."
                 while i < r.lr_index:
                      if r.prod[i] != p.prod[i+1]: break
                      i = i + 1
                 else:
                      lookb.append((j,r))
        for i in includes:
             if not includedict.has_key(i): includedict[i] = []
             includedict[i].append((state,N))
        lookdict[(state,N)] = lookb

    return lookdict,includedict

# -----------------------------------------------------------------------------
# digraph()
# traverse()
#
# The following two functions are used to compute set valued functions
# of the form:
#
#     F(x) = F'(x) U U{F(y) | x R y}
#
# This is used to compute the values of Read() sets as well as FOLLOW sets
# in LALR(1) generation.
#
# Inputs:  X    - An input set
#          R    - A relation
#          FP   - Set-valued function
# ------------------------------------------------------------------------------

def digraph(X,R,FP):
    N = { }
    for x in X:
       N[x] = 0
    stack = []
    F = { }
    for x in X:
        if N[x] == 0: traverse(x,N,stack,F,X,R,FP)
    return F

def traverse(x,N,stack,F,X,R,FP):
    stack.append(x)
    d = len(stack)
    N[x] = d
    F[x] = FP(x)             # F(X) <- F'(x)
    
    rel = R(x)               # Get y's related to x
    for y in rel:
        if N[y] == 0:
             traverse(y,N,stack,F,X,R,FP)
        N[x] = min(N[x],N[y])
        for a in F.get(y,[]):
            if a not in F[x]: F[x].append(a)
    if N[x] == d:
       N[stack[-1]] = sys.maxint
       F[stack[-1]] = F[x]
       element = stack.pop()
       while element != x:
           N[stack[-1]] = sys.maxint
           F[stack[-1]] = F[x]
           element = stack.pop()

# -----------------------------------------------------------------------------
# compute_read_sets()
#
# Given a set of LR(0) items, this function computes the read sets.
#
# Inputs:  C        =  Set of LR(0) items
#          ntrans   = Set of nonterminal transitions
#          nullable = Set of empty transitions
#
# Returns a set containing the read sets
# -----------------------------------------------------------------------------

def compute_read_sets(C, ntrans, nullable):
    FP = lambda x: dr_relation(C,x,nullable)
    R =  lambda x: reads_relation(C,x,nullable)
    F = digraph(ntrans,R,FP)
    return F

# -----------------------------------------------------------------------------
# compute_follow_sets()
#
# Given a set of LR(0) items, a set of non-terminal transitions, a readset, 
# and an include set, this function computes the follow sets
#
# Follow(p,A) = Read(p,A) U U {Follow(p',B) | (p,A) INCLUDES (p',B)}
#
# Inputs:    
#            ntrans     = Set of nonterminal transitions
#            readsets   = Readset (previously computed)
#            inclsets   = Include sets (previously computed)
#
# Returns a set containing the follow sets      
# -----------------------------------------------------------------------------

def compute_follow_sets(ntrans,readsets,inclsets):
     FP = lambda x: readsets[x]
     R  = lambda x: inclsets.get(x,[])
     F = digraph(ntrans,R,FP)
     return F

# -----------------------------------------------------------------------------
# add_lookaheads()
#
# Attaches the lookahead symbols to grammar rules. 
#
# Inputs:    lookbacks         -  Set of lookback relations
#            followset         -  Computed follow set
#
# This function directly attaches the lookaheads to productions contained
# in the lookbacks set
# -----------------------------------------------------------------------------

def add_lookaheads(lookbacks,followset):
    for trans,lb in lookbacks.items():
        # Loop over productions in lookback
        for state,p in lb:
             if not p.lookaheads.has_key(state):
                  p.lookaheads[state] = []
             f = followset.get(trans,[])
             for a in f:
                  if a not in p.lookaheads[state]: p.lookaheads[state].append(a)

# -----------------------------------------------------------------------------
# add_lalr_lookaheads()
#
# This function does all of the work of adding lookahead information for use
# with LALR parsing
# -----------------------------------------------------------------------------

def add_lalr_lookaheads(C):
    # Determine all of the nullable nonterminals
    nullable = compute_nullable_nonterminals()

    # Find all non-terminal transitions
    trans = find_nonterminal_transitions(C)

    # Compute read sets
    readsets = compute_read_sets(C,trans,nullable)

    # Compute lookback/includes relations
    lookd, included = compute_lookback_includes(C,trans,nullable)

    # Compute LALR FOLLOW sets
    followsets = compute_follow_sets(trans,readsets,included)
    
    # Add all of the lookaheads
    add_lookaheads(lookd,followsets)

# -----------------------------------------------------------------------------
# lr_parse_table()
#
# This function constructs the parse tables for SLR or LALR
# -----------------------------------------------------------------------------
def lr_parse_table(method):
    global _lr_method
    goto = _lr_goto           # Goto array
    action = _lr_action       # Action array
    actionp = { }             # Action production array (temporary)

    _lr_method = method
    
    n_srconflict = 0
    n_rrconflict = 0

    if yaccdebug:
        sys.stderr.write("yacc: Generating %s parsing table...\n" % method)        
        _vf.write("\n\nParsing method: %s\n\n" % method)
        
    # Step 1: Construct C = { I0, I1, ... IN}, collection of LR(0) items
    # This determines the number of states
    
    C = lr0_items()

    if method == 'LALR':
        add_lalr_lookaheads(C)

    # Build the parser table, state by state
    st = 0
    for I in C:
        # Loop over each production in I
        actlist = [ ]              # List of actions
        
        if yaccdebug:
            _vf.write("\nstate %d\n\n" % st)
            for p in I:
                _vf.write("    (%d) %s\n" % (p.number, str(p)))
            _vf.write("\n")

        for p in I:
            try:
                if p.prod[-1] == ".":
                    if p.name == "S'":
                        # Start symbol. Accept!
                        action[st,"$end"] = 0
                        actionp[st,"$end"] = p
                    else:
                        # We are at the end of a production.  Reduce!
                        if method == 'LALR':
                            laheads = p.lookaheads[st]
                        else:
                            laheads = Follow[p.name]
                        for a in laheads:
                            actlist.append((a,p,"reduce using rule %d (%s)" % (p.number,p)))
                            r = action.get((st,a),None)
                            if r is not None:
                                # Whoa. Have a shift/reduce or reduce/reduce conflict
                                if r > 0:
                                    # Need to decide on shift or reduce here
                                    # By default we favor shifting. Need to add
                                    # some precedence rules here.
                                    sprec,slevel = Productions[actionp[st,a].number].prec                                    
                                    rprec,rlevel = Precedence.get(a,('right',0))
                                    if (slevel < rlevel) or ((slevel == rlevel) and (rprec == 'left')):
                                        # We really need to reduce here.  
                                        action[st,a] = -p.number
                                        actionp[st,a] = p
                                        if not slevel and not rlevel:
                                            _vfc.write("shift/reduce conflict in state %d resolved as reduce.\n" % st)
                                            _vf.write("  ! shift/reduce conflict for %s resolved as reduce.\n" % a)
                                            n_srconflict += 1
                                    elif (slevel == rlevel) and (rprec == 'nonassoc'):
                                        action[st,a] = None
                                    else:
                                        # Hmmm. Guess we'll keep the shift
                                        if not rlevel:
                                            _vfc.write("shift/reduce conflict in state %d resolved as shift.\n" % st)
                                            _vf.write("  ! shift/reduce conflict for %s resolved as shift.\n" % a)
                                            n_srconflict +=1                                    
                                elif r < 0:
                                    # Reduce/reduce conflict.   In this case, we favor the rule
                                    # that was defined first in the grammar file
                                    oldp = Productions[-r]
                                    pp = Productions[p.number]
                                    if oldp.line > pp.line:
                                        action[st,a] = -p.number
                                        actionp[st,a] = p
                                    # sys.stderr.write("Reduce/reduce conflict in state %d\n" % st)
                                    n_rrconflict += 1
                                    _vfc.write("reduce/reduce conflict in state %d resolved using rule %d (%s).\n" % (st, actionp[st,a].number, actionp[st,a]))
                                    _vf.write("  ! reduce/reduce conflict for %s resolved using rule %d (%s).\n" % (a,actionp[st,a].number, actionp[st,a]))
                                else:
                                    sys.stderr.write("Unknown conflict in state %d\n" % st)
                            else:
                                action[st,a] = -p.number
                                actionp[st,a] = p
                else:
                    i = p.lr_index
                    a = p.prod[i+1]       # Get symbol right after the "."
                    if Terminals.has_key(a):
                        g = lr0_goto(I,a)
                        j = _lr0_cidhash.get(id(g),-1)
                        if j >= 0:
                            # We are in a shift state
                            actlist.append((a,p,"shift and go to state %d" % j))
                            r = action.get((st,a),None)
                            if r is not None:
                                # Whoa have a shift/reduce or shift/shift conflict
                                if r > 0:
                                    if r != j:
                                        sys.stderr.write("Shift/shift conflict in state %d\n" % st)
                                elif r < 0:
                                    # Do a precedence check.
                                    #   -  if precedence of reduce rule is higher, we reduce.
                                    #   -  if precedence of reduce is same and left assoc, we reduce.
                                    #   -  otherwise we shift
                                    rprec,rlevel = Productions[actionp[st,a].number].prec
                                    sprec,slevel = Precedence.get(a,('right',0))
                                    if (slevel > rlevel) or ((slevel == rlevel) and (rprec != 'left')):
                                        # We decide to shift here... highest precedence to shift
                                        action[st,a] = j
                                        actionp[st,a] = p
                                        if not rlevel:
                                            n_srconflict += 1
                                            _vfc.write("shift/reduce conflict in state %d resolved as shift.\n" % st)
                                            _vf.write("  ! shift/reduce conflict for %s resolved as shift.\n" % a)
                                    elif (slevel == rlevel) and (rprec == 'nonassoc'):
                                        action[st,a] = None
                                    else:                                            
                                        # Hmmm. Guess we'll keep the reduce
                                        if not slevel and not rlevel:
                                            n_srconflict +=1
                                            _vfc.write("shift/reduce conflict in state %d resolved as reduce.\n" % st)
                                            _vf.write("  ! shift/reduce conflict for %s resolved as reduce.\n" % a)
                                            
                                else:
                                    sys.stderr.write("Unknown conflict in state %d\n" % st)
                            else:
                                action[st,a] = j
                                actionp[st,a] = p
                                
            except StandardError,e:
                raise YaccError, "Hosed in lr_parse_table", e

        # Print the actions associated with each terminal
        if yaccdebug:
          _actprint = { }
          for a,p,m in actlist:
            if action.has_key((st,a)):
                if p is actionp[st,a]:
                    _vf.write("    %-15s %s\n" % (a,m))
                    _actprint[(a,m)] = 1
          _vf.write("\n")
          for a,p,m in actlist:
            if action.has_key((st,a)):
                if p is not actionp[st,a]:
                    if not _actprint.has_key((a,m)):
                        _vf.write("  ! %-15s [ %s ]\n" % (a,m))
                        _actprint[(a,m)] = 1
            
        # Construct the goto table for this state
        if yaccdebug:
            _vf.write("\n")
        nkeys = { }
        for ii in I:
            for s in ii.usyms:
                if Nonterminals.has_key(s):
                    nkeys[s] = None
        for n in nkeys.keys():
            g = lr0_goto(I,n)
            j = _lr0_cidhash.get(id(g),-1)            
            if j >= 0:
                goto[st,n] = j
                if yaccdebug:
                    _vf.write("    %-30s shift and go to state %d\n" % (n,j))

        st += 1

    if yaccdebug:
        if n_srconflict == 1:
            sys.stderr.write("yacc: %d shift/reduce conflict\n" % n_srconflict)
        if n_srconflict > 1:
            sys.stderr.write("yacc: %d shift/reduce conflicts\n" % n_srconflict)
        if n_rrconflict == 1:
            sys.stderr.write("yacc: %d reduce/reduce conflict\n" % n_rrconflict)
        if n_rrconflict > 1:
            sys.stderr.write("yacc: %d reduce/reduce conflicts\n" % n_rrconflict)

# -----------------------------------------------------------------------------
#                          ==== LR Utility functions ====
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# _lr_write_tables()
#
# This function writes the LR parsing tables to a file
# -----------------------------------------------------------------------------

def lr_write_tables(modulename=tab_module,outputdir=''):
    filename = os.path.join(outputdir,modulename) + ".py"
    try:
        f = open(filename,"w")

        f.write("""
# %s
# This file is automatically generated. Do not edit.

_lr_method = %s

_lr_signature = %s
""" % (filename, repr(_lr_method), repr(Signature.digest())))

        # Change smaller to 0 to go back to original tables
        smaller = 1
                
        # Factor out names to try and make smaller
        if smaller:
            items = { }
        
            for k,v in _lr_action.items():
                i = items.get(k[1])
                if not i:
                    i = ([],[])
                    items[k[1]] = i
                i[0].append(k[0])
                i[1].append(v)

            f.write("\n_lr_action_items = {")
            for k,v in items.items():
                f.write("%r:([" % k)
                for i in v[0]:
                    f.write("%r," % i)
                f.write("],[")
                for i in v[1]:
                    f.write("%r," % i)
                           
                f.write("]),")
            f.write("}\n")

            f.write("""
_lr_action = { }
for _k, _v in _lr_action_items.items():
   for _x,_y in zip(_v[0],_v[1]):
       _lr_action[(_x,_k)] = _y
del _lr_action_items
""")
            
        else:
            f.write("\n_lr_action = { ");
            for k,v in _lr_action.items():
                f.write("(%r,%r):%r," % (k[0],k[1],v))
            f.write("}\n");

        if smaller:
            # Factor out names to try and make smaller
            items = { }
        
            for k,v in _lr_goto.items():
                i = items.get(k[1])
                if not i:
                    i = ([],[])
                    items[k[1]] = i
                i[0].append(k[0])
                i[1].append(v)

            f.write("\n_lr_goto_items = {")
            for k,v in items.items():
                f.write("%r:([" % k)
                for i in v[0]:
                    f.write("%r," % i)
                f.write("],[")
                for i in v[1]:
                    f.write("%r," % i)
                           
                f.write("]),")
            f.write("}\n")

            f.write("""
_lr_goto = { }
for _k, _v in _lr_goto_items.items():
   for _x,_y in zip(_v[0],_v[1]):
       _lr_goto[(_x,_k)] = _y
del _lr_goto_items
""")
        else:
            f.write("\n_lr_goto = { ");
            for k,v in _lr_goto.items():
                f.write("(%r,%r):%r," % (k[0],k[1],v))                    
            f.write("}\n");

        # Write production table
        f.write("_lr_productions = [\n")
        for p in Productions:
            if p:
                if (p.func):
                    f.write("  (%r,%d,%r,%r,%d),\n" % (p.name, p.len, p.func.__name__,p.file,p.line))
                else:
                    f.write("  (%r,%d,None,None,None),\n" % (p.name, p.len))
            else:
                f.write("  None,\n")
        f.write("]\n")
        
        f.close()

    except IOError,e:
        print "Unable to create '%s'" % filename
        print e
        return

def lr_read_tables(module=tab_module,optimize=0):
    global _lr_action, _lr_goto, _lr_productions, _lr_method
    try:
        exec "import %s as parsetab" % module
        
        if (optimize) or (Signature.digest() == parsetab._lr_signature):
            _lr_action = parsetab._lr_action
            _lr_goto   = parsetab._lr_goto
            _lr_productions = parsetab._lr_productions
            _lr_method = parsetab._lr_method
            return 1
        else:
            return 0
        
    except (ImportError,AttributeError):
        return 0


# Available instance types.  This is used when parsers are defined by a class.
# it's a little funky because I want to preserve backwards compatibility
# with Python 2.0 where types.ObjectType is undefined.

try:
   _INSTANCETYPE = (types.InstanceType, types.ObjectType)
except AttributeError:
   _INSTANCETYPE = types.InstanceType

# -----------------------------------------------------------------------------
# yacc(module)
#
# Build the parser module
# -----------------------------------------------------------------------------

def yacc(method=default_lr, debug=yaccdebug, module=None, tabmodule=tab_module, start=None, check_recursion=1, optimize=0,write_tables=1,debugfile=debug_file,outputdir=''):
    global yaccdebug
    yaccdebug = debug
    
    initialize_vars()
    files = { }
    error = 0


    # Add parsing method to signature
    Signature.update(method)
    
    # If a "module" parameter was supplied, extract its dictionary.
    # Note: a module may in fact be an instance as well.
    
    if module:
        # User supplied a module object.
        if isinstance(module, types.ModuleType):
            ldict = module.__dict__
        elif isinstance(module, _INSTANCETYPE):
            _items = [(k,getattr(module,k)) for k in dir(module)]
            ldict = { }
            for i in _items:
                ldict[i[0]] = i[1]
        else:
            raise ValueError,"Expected a module"
        
    else:
        # No module given.  We might be able to get information from the caller.
        # Throw an exception and unwind the traceback to get the globals
        
        try:
            raise RuntimeError
        except RuntimeError:
            e,b,t = sys.exc_info()
            f = t.tb_frame
            f = f.f_back           # Walk out to our calling function
            ldict = f.f_globals    # Grab its globals dictionary

    # Add starting symbol to signature
    if not start:
        start = ldict.get("start",None)
    if start:
        Signature.update(start)

    # If running in optimized mode.  We're going to

    if (optimize and lr_read_tables(tabmodule,1)):
        # Read parse table
        del Productions[:]
        for p in _lr_productions:
            if not p:
                Productions.append(None)
            else:
                m = MiniProduction()
                m.name = p[0]
                m.len  = p[1]
                m.file = p[3]
                m.line = p[4]
                if p[2]:
                    m.func = ldict[p[2]]
                Productions.append(m)
        
    else:
        # Get the tokens map
        if (module and isinstance(module,_INSTANCETYPE)):
            tokens = getattr(module,"tokens",None)
        else:
            tokens = ldict.get("tokens",None)
    
        if not tokens:
            raise YaccError,"module does not define a list 'tokens'"
        if not (isinstance(tokens,types.ListType) or isinstance(tokens,types.TupleType)):
            raise YaccError,"tokens must be a list or tuple."

        # Check to see if a requires dictionary is defined.
        requires = ldict.get("require",None)
        if requires:
            if not (isinstance(requires,types.DictType)):
                raise YaccError,"require must be a dictionary."

            for r,v in requires.items():
                try:
                    if not (isinstance(v,types.ListType)):
                        raise TypeError
                    v1 = [x.split(".") for x in v]
                    Requires[r] = v1
                except StandardError:
                    print "Invalid specification for rule '%s' in require. Expected a list of strings" % r            

        
        # Build the dictionary of terminals.  We a record a 0 in the
        # dictionary to track whether or not a terminal is actually
        # used in the grammar

        if 'error' in tokens:
            print "yacc: Illegal token 'error'.  Is a reserved word."
            raise YaccError,"Illegal token name"

        for n in tokens:
            if Terminals.has_key(n):
                print "yacc: Warning. Token '%s' multiply defined." % n
            Terminals[n] = [ ]

        Terminals['error'] = [ ]

        # Get the precedence map (if any)
        prec = ldict.get("precedence",None)
        if prec:
            if not (isinstance(prec,types.ListType) or isinstance(prec,types.TupleType)):
                raise YaccError,"precedence must be a list or tuple."
            add_precedence(prec)
            Signature.update(repr(prec))

        for n in tokens:
            if not Precedence.has_key(n):
                Precedence[n] = ('right',0)         # Default, right associative, 0 precedence

        # Look for error handler
        ef = ldict.get('p_error',None)
        if ef:
            if isinstance(ef,types.FunctionType):
                ismethod = 0
            elif isinstance(ef, types.MethodType):
                ismethod = 1
            else:
                raise YaccError,"'p_error' defined, but is not a function or method."                
            eline = ef.func_code.co_firstlineno
            efile = ef.func_code.co_filename
            files[efile] = None

            if (ef.func_code.co_argcount != 1+ismethod):
                raise YaccError,"%s:%d: p_error() requires 1 argument." % (efile,eline)
            global Errorfunc
            Errorfunc = ef
        else:
            print "yacc: Warning. no p_error() function is defined."
            
        # Get the list of built-in functions with p_ prefix
        symbols = [ldict[f] for f in ldict.keys()
               if (type(ldict[f]) in (types.FunctionType, types.MethodType) and ldict[f].__name__[:2] == 'p_'
                   and ldict[f].__name__ != 'p_error')]

        # Check for non-empty symbols
        if len(symbols) == 0:
            raise YaccError,"no rules of the form p_rulename are defined."
    
        # Sort the symbols by line number
        symbols.sort(lambda x,y: cmp(x.func_code.co_firstlineno,y.func_code.co_firstlineno))

        # Add all of the symbols to the grammar
        for f in symbols:
            if (add_function(f)) < 0:
                error += 1
            else:
                files[f.func_code.co_filename] = None

        # Make a signature of the docstrings
        for f in symbols:
            if f.__doc__:
                Signature.update(f.__doc__)
    
        lr_init_vars()

        if error:
            raise YaccError,"Unable to construct parser."

        if not lr_read_tables(tabmodule):

            # Validate files
            for filename in files.keys():
                if not validate_file(filename):
                    error = 1

            # Validate dictionary
            validate_dict(ldict)

            if start and not Prodnames.has_key(start):
                raise YaccError,"Bad starting symbol '%s'" % start
        
            augment_grammar(start)    
            error = verify_productions(cycle_check=check_recursion)
            otherfunc = [ldict[f] for f in ldict.keys()
               if (type(f) in (types.FunctionType,types.MethodType) and ldict[f].__name__[:2] != 'p_')]

            if error:
                raise YaccError,"Unable to construct parser."
            
            build_lritems()
            compute_first1()
            compute_follow(start)
        
            if method in ['SLR','LALR']:
                lr_parse_table(method)
            else:
                raise YaccError, "Unknown parsing method '%s'" % method

            if write_tables:
                lr_write_tables(tabmodule,outputdir)        
    
            if yaccdebug:
                try:
                    f = open(os.path.join(outputdir,debugfile),"w")
                    f.write(_vfc.getvalue())
                    f.write("\n\n")
                    f.write(_vf.getvalue())
                    f.close()
                except IOError,e:
                    print "yacc: can't create '%s'" % debugfile,e
        
    # Made it here.   Create a parser object and set up its internal state.
    # Set global parse() method to bound method of parser object.

    p = Parser("xyzzy")
    p.productions = Productions
    p.errorfunc = Errorfunc
    p.action = _lr_action
    p.goto   = _lr_goto
    p.method = _lr_method
    p.require = Requires

    global parse
    parse = p.parse

    global parser
    parser = p

    # Clean up all of the globals we created
    if (not optimize):
        yacc_cleanup()
    return p

# yacc_cleanup function.  Delete all of the global variables
# used during table construction

def yacc_cleanup():
    global _lr_action, _lr_goto, _lr_method, _lr_goto_cache
    del _lr_action, _lr_goto, _lr_method, _lr_goto_cache

    global Productions, Prodnames, Prodmap, Terminals 
    global Nonterminals, First, Follow, Precedence, LRitems
    global Errorfunc, Signature, Requires
    
    del Productions, Prodnames, Prodmap, Terminals
    del Nonterminals, First, Follow, Precedence, LRitems
    del Errorfunc, Signature, Requires
    
    global _vf, _vfc
    del _vf, _vfc
    
    
# Stub that raises an error if parsing is attempted without first calling yacc()
def parse(*args,**kwargs):
    raise YaccError, "yacc: No parser built with yacc()"

