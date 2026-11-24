# Capture generators

The synthetic captures in `test/captures` whose names contain `_coverage`
(and a few reproducer captures and data files next to them) are made by the
Python scripts in this directory. Every packet is built by these scripts;
nothing comes from a real network.

## Layout

- `<name>/mk<name>.py` writes the captures of one dissector or file format.
  Some directories have more than one generator (`amqp`: AMQP 0-x, AMQP 1.0
  and the merged capture) or helper modules of their own.
- `shared/` holds the modules shared by several generators. `capgen.py` has the
  building blocks: checksums, Ethernet/IP/UDP/TCP/SCTP headers, exported PDU
  tags and the pcap and pcapng writers. Most of the other modules are
  encoders for one protocol family (BER/PER, NDR, RDP, SMB, USB, ...).
  A module in a generator's directory takes precedence over one of the
  same name in `shared/`.
- Reproducer scripts (bug reproducers whose frames a capture includes) sit
  next to the generator that uses them; `shared/repro.py` runs them in a
  temporary directory.

## Running a generator

    python3 test/captures/generators/dns/mkdns.py <output directory>

writes `dns-coverage.pcap` and the other files of that generator into the
output directory (the current directory by default). The committed capture
is the gzipped main file, renamed to the `test/captures` convention
(`dns-coverage.pcap` becomes `dns_coverage.pcap.gz`). Most generators also
write captures that are not committed: `-malformed` captures with damaged
or truncated input, used to measure code coverage and for fuzzing.

The generators run from the source tree: some read dissector sources,
ASN.1 modules (`epan/dissectors/asn1`) or PIDL files
(`epan/dissectors/pidl`).

## Requirements

- Python 3 (tested with 3.14). Most generators use only the standard
  library.
- `asn1tools` (pip) for the generators of PER-encoded ASN.1 protocols
  (`per`, `rua`, `s1ap`, `sabp`, `sbc_ap`, `ulp`, `z3950` and the users of
  `shared/asnlib.py`, `shared/asngen.py` and `shared/asnsample.py`).
- `cryptography` (pip) for the generators that encrypt (`btmesh`,
  `btmesh_proxy`, `cemi`, `coap`, `dof`, `dtls`, `edhoc`), and `aioquic`
  (pip) for `quic_decrypt` and `http3_decrypt`.
- Perl with `JSON::PP` and `Parse::Yapp` for the DCE/RPC generators that
  read PIDL files through `shared/idl2json.pl`.
- A tshark for the few generators that check candidate frames with it:
  set `TSHARK` to its path, otherwise `tshark` is taken from `PATH`.

## Reproducibility

Running a generator recreates its committed capture byte for byte, with
these exceptions:

- `kerberos`, `dcerpc_netlogon`, `quic_decrypt` and `http3_decrypt` use
  random keys and nonces from the cryptography libraries. Their output has
  the same frames and dissects the same way, but the bytes differ on every
  run. In `quic_decrypt` the number of deliberately damaged packets that
  fail to decrypt also varies (three to five) from run to run.
- Generators that keep only candidate frames tshark decodes cleanly
  (`ranap`, `rnsap`, `rrc`, `rrlp`, `rua`, `s1ap`, `sabp`, `sbc_ap`, ...)
  depend on the tshark they run; a newer tshark can accept or reject other
  candidates.

## Adding a generator

- Create `<name>/mk<name>.py`, taking the output directory as its only
  argument, with the license header used by the other generators.
- Use `shared/capgen.py` for headers, checksums and capture files, and pass
  addresses, ports and timestamps explicitly.
- Use documentation addresses (192.0.2.0/24, 198.51.100.0/24,
  203.0.113.0/24, 2001:db8::/32) and example domains.
- Make the output deterministic: seed every random generator.
