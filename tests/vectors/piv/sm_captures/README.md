<!--
SPDX-FileCopyrightText: Mistial Dev
SPDX-License-Identifier: GPL-2.0-or-later
-->

# PIV secure messaging captures

Byte-exact copies of four PIV secure messaging captures from physical NIST
Special Database 33 cards, replayed at the wire level by
`test_sm_primitives_corpus` (`tests/piv/sm_corpus.py` and
`tests/piv/sm_apdu_replay.c`). Vendored 2026-09-30. `SHA256SUMS` lists every
file.

| File | Source | Captured | Card | Interface | Suite |
| --- | --- | --- | --- | --- | --- |
| `nist_special_database_33_card_2.json` | PIV Subcommittee `nist_sd_33_vectors_v2` | 2026-03-05 | SD 33 card 2 | contactless (Proxmark3) | CS7, P-384 card CVC |
| `nist_special_database_33_card_4.json` | PIV Subcommittee `nist_sd_33_vectors_v2` | 2026-03-05 | SD 33 card 4 | contactless (Proxmark3) | CS2, P-256 card CVC |
| `vci_contactless_card01.json` | PIV Subcommittee `sm_vci_vectors` | 2026-02-16 | SD 33 card 2 | contactless | CS7, P-384 card CVC |
| `vci_vectors_card01.json` | PIV Subcommittee `sm_vci_vectors` | 2026-02-15 | SD 33 card 2 | contact | CS7, P-384 card CVC |

The PIV Authentication, Card Authentication and signing keys of these cards
are RSA-2048. `vci_contactless_card01.json` records the GENERAL AUTHENTICATE
chains for keys 9E and 9A fragment by fragment.

## Licence

The capturer of both sets relicensed them for this project. The decision of
2026-09-30 reads: "The user captured both vector sets (sm_vci_vectors and
nist_sd_33_vectors_v2); neither is published. Vendor them under the library
licence GPL-2.0-or-later". The files are distributed under GPL-2.0-or-later
with the rest of the library. The MIT No Attribution notice of the
`sm_vci_vectors` source directory is not carried over.

## Test credentials

The captures hold the published SD 33 test credentials in plaintext, in their
metadata and in the VERIFY commands: PIN `123456` (`31 32 33 34 35 36 FF FF`)
for all four, pairing code `00000002` for card 2 and `00000004` for card 4.
They are published test values of the SD 33 cards. Keep real credentials out
of this directory.

## Replay notes

- The v2 captures hold derivation data for event 2 only. Event 1 objects serve
  as recorded plaintext.
- The captures record merged answers after GET RESPONSE. The adapter splits
  answers above 256 bytes into 256-byte chunks with `61XX` and plain
  `00 C0 00 00 XX`.
- The v2 middleware sent the GENERAL AUTHENTICATE of keys 9A, 9C and 9D as
  extended length secure messaging. SP 800-73-5 Part 2 footnote 22 fixes a
  one-byte Le, so the library sends SHORT `1C` chains. The adapter replays
  those SM data fields as the chain, and the recorded C-MAC over the
  unfragmented field matches the library's bytes for every replayed command.
- Plain commands between protected ones, such as the Card Authentication
  GENERAL AUTHENTICATE of the v2 captures, are skipped.
