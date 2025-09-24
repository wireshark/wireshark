# Asterix parser generator

*Asterix* is a set of standards, where each standard is defined
as so called *asterix category*.
In addition, each *asterix category* is potentially released
in number of editions. Normally, newer editions of the same category
are backward compatible, however in general, there is no such guarantie.

Structured version of asterix specifications is maintained in a separate
project: <https://zoranbosnjak.github.io/asterix-specs/specs.html>

Structure of asterix dissector and support files:

```
tools/asterix/*                            - support files for asterix specs conversion
epan/dissectors/packet-asterix.c           - actual dissector
epan/dissectors/packet-asterix.h           - common definitions
epan/dissectors/packet-asterix-generated.h - generated file (do not edit manually)
```

## Manual update procedure

To sync with the upstream asterix specifications, run:

```bash
# show current upstream git revision (for reference)
export ASTERIX_SPECS_REV=$(./tools/asterix/update-specs.py --reference)
echo $ASTERIX_SPECS_REV

# update asterix decoder
./tools/asterix/update-specs.py > epan/dissectors/packet-asterix-generated.h
git add epan/dissectors/packet-asterix-generated.h

# inspect change, rebuild project, test...

# commit change, with reference to upstream version
git commit -m "asterix: Sync with asterix-specs #$ASTERIX_SPECS_REV"
```

## Automatic update procedure

To integrate asterix updates to a periodic (GitLab CI) job, use `--update {file}`
option. For example:

```
...
# Asterix categories.
- ./tools/asterix/update-specs.py --update epan/dissectors/packet-asterix-generated.h \
     || echo "asterix failed." >> commit-message.txt
- COMMIT_FILES+=("epan/dissectors/packet-asterix-generated.h")
...
```
