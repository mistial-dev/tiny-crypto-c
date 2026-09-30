<!--
SPDX-FileCopyrightText: Mistial Dev
SPDX-License-Identifier: GPL-2.0-or-later
-->

# piv_inspect golden outputs

The text `examples/piv_inspect.c` prints for the SD 33 card simulator runs of
`tests/piv/inspect_replay.c`:

| File | Card | Interface |
| --- | --- | --- |
| `sd33_card2_contactless.txt` | SD 33 card 2 (CS7, RSA-2048) | contactless, secure messaging, paired VCI, PIN |
| `sd33_card2_contact.txt` | SD 33 card 2 | contact, secure messaging, PIN |
| `sd33_card4_contactless.txt` | SD 33 card 4 (CS2, P-256) | contactless, secure messaging, paired VCI, PIN |

The example wrote these files. The trust inputs are the pinned issuing CAs,
the CRLs of `../../x509/crl/sd33` and the OCSP responses of
`../../x509/ocsp/sd33`, evaluated at 2026-09-29T18:00:00Z. The outputs hold
card identifiers and certificate fields of the published SD 33 test cards, and
neither the PIN nor the pairing code.

When the output format changes, the test writes `<name>.actual` in its working
directory. Review the difference and copy the file here.
