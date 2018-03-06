/* based on http://llvm.org/svn/llvm-project/compiler-rt/trunk/lib/fuzzer/standalone/StandaloneFuzzTargetMain.c r311407 (22 Aug 2017) */

/* http://llvm.org/svn/llvm-project/compiler-rt/trunk/LICENSE.TXT follows */

/*
==============================================================================
compiler_rt License
==============================================================================

The compiler_rt library is dual licensed under both the University of Illinois
"BSD-Like" license and the MIT license.  As a user of this code you may choose
to use it under either license.  As a contributor, you agree to allow your code
to be used under both.

Full text of the relevant licenses is included below.

==============================================================================

University of Illinois/NCSA
Open Source License

Copyright (c) 2009-2016 by the contributors listed in CREDITS.TXT

All rights reserved.

Developed by:

    LLVM Team

    University of Illinois at Urbana-Champaign

    http://llvm.org

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal with
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimers.

    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimers in the
      documentation and/or other materials provided with the distribution.

    * Neither the names of the LLVM Team, University of Illinois at
      Urbana-Champaign, nor the names of its contributors may be used to
      endorse or promote products derived from this Software without specific
      prior written permission.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS WITH THE
SOFTWARE.

==============================================================================

Copyright (c) 2009-2015 by the contributors listed in CREDITS.TXT

SPDX-License-Identifier: MIT

==============================================================================
Copyrights and Licenses for Third Party Software Distributed with LLVM:
==============================================================================
The LLVM software contains code written by third parties.  Such software will
have its own individual LICENSE.TXT file in the directory in which it appears.
This file will describe the copyrights, license, and restrictions which apply
to that code.

The disclaimer of warranty in the University of Illinois Open Source License
applies to all code in the LLVM Distribution, and nothing in any of the
other licenses gives permission to use the names of the LLVM Team or the
University of Illinois to endorse or promote products derived from this
Software.
*/

/*===- StandaloneFuzzTargetMain.c - standalone main() for fuzz targets. ---===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// This main() function can be linked to a fuzz target (i.e. a library
// that exports LLVMFuzzerTestOneInput() and possibly LLVMFuzzerInitialize())
// instead of libFuzzer. This main() function will not perform any fuzzing
// but will simply feed all input files one by one to the fuzz target.
//
// Use this file to provide reproducers for bugs when linking against libFuzzer
// or other fuzzing engine is undesirable.
//===----------------------------------------------------------------------===*/
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <glib.h>
#include <wsutil/file_util.h>

#include "FuzzerInterface.h"

int main(int argc, char **argv) {
  fprintf(stderr, "StandaloneFuzzTargetMain: running %d inputs\n", argc - 1);
  LLVMFuzzerInitialize(&argc, &argv);
  for (int i = 1; i < argc; i++) {
    fprintf(stderr, "Running: %s\n", argv[i]);
    FILE *f = ws_fopen(argv[i], "r");
    assert(f);
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    assert(len >= 0);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = (unsigned char*)g_malloc((size_t)len);
    size_t n_read = fread(buf, 1, len, f);
    assert(n_read == (size_t)len);
    fclose(f);
    LLVMFuzzerTestOneInput(buf, len);
    g_free(buf);
    fprintf(stderr, "Done:    %s: (%zd bytes)\n", argv[i], n_read);
  }
}
