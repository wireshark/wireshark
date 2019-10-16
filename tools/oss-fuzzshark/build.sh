#!/bin/bash -eux
# Copyright 2017 Google Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

# TODO: support specifing targets in args. Google oss-fuzz specifies 'all'.

# TODO update oss-fuzz configuration to build with OSS_FUZZ=1? This is necessary
# to build the fuzzshark_* targets for oss-fuzz.
cmake -DOSS_FUZZ=1 .

cmake --build . --target all-fuzzers

for file in run/fuzzshark_*; do
  fuzzer_name="${file##*/}"
  fuzzer_target="${fuzzer_name#fuzzshark_}"
  mv "$file" "$OUT/"
  echo -en "[libfuzzer]\nmax_len = 1024\n" > $OUT/${fuzzer_name}.options
  if [ -d "$SAMPLES_DIR/${fuzzer_target}" ]; then
    zip -j $OUT/${fuzzer_name}_seed_corpus.zip $SAMPLES_DIR/${fuzzer_target}/*/*.bin
  fi
done
