#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Measure linked AVR flash and conservative project stack call chains.

Uses compiler stack reports and emitted assembly, including possible indirect
callees whose addresses are taken in each translation unit. Tail calls are
counted as nested calls, so the estimate can overcount. libc/compiler helpers,
interrupts, the application caller and application callbacks such as a DRBG
entropy source are excluded and listed explicitly.
This is a regression measurement, not a whole-firmware stack-safety proof.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CC = os.environ.get("AVR_CC", "avr-gcc")
SIZE = os.environ.get("AVR_SIZE", "avr-size")
NM = os.environ.get("AVR_NM", "avr-nm")
BASE = ["-std=c99", "-Os", "-mmcu=atmega328p", "-ffunction-sections",
        "-fdata-sections", "-fstack-usage", "-I" + str(ROOT / "src")]
PROFILES = {
    "aes_ctr": ([], """
      struct TC_AES_ctx ctx;
      if (TC_AES_init(&ctx, key) != TC_OK || TC_AES_set_iv(&ctx, iv) != TC_OK) return 1;
      return TC_AES_CTR_crypt(&ctx, out, sizeof(out)) != TC_OK;
    """, "TC_AES_CTR_crypt"),
    # KW and KWP at AES-128 with fixed keys. Each call expands the KEK on the
    # stack. Unwrap is the deepest entry.
    "aes_kw": (["TC_AES_ENABLE_KW=1", "TC_AES_ENABLE_CTR=0"], """
      const TC_bytes kek = {key, 16};
      size_t length;
      if (TC_AES_KW_wrap(kek, (TC_bytes){iv, 16}, (TC_buffer){out, 24}) != TC_OK) return 1;
      if (TC_AES_KW_unwrap(kek, (TC_bytes){out, 24}, (TC_buffer){iv, 16}) != TC_OK) return 1;
      if (TC_AES_KWP_wrap(kek, (TC_bytes){iv, 7}, (TC_buffer){out, 16}) != TC_OK) return 1;
      return TC_AES_KWP_unwrap(kek, (TC_bytes){out, 16}, (TC_buffer){iv, 8}, &length) != TC_OK;
    """, "TC_AES_KWP_unwrap"),
    "kdf_sha256": (["TC_ENABLE_HMAC=1", "TC_ENABLE_KDF=1"], """
      struct TC_KBKDF_params p = {32, 1, 0};
      return TC_KBKDF_HMAC_SHA256_counter((TC_bytes){key, sizeof(key)}, &p, (TC_bytes){NULL, 0}, (TC_bytes){iv, sizeof(iv)}, (TC_buffer){out, sizeof(out)}) != TC_OK;
    """, "TC_KBKDF_HMAC_SHA256_counter"),
    "kdf_mixed": ([
        "TC_ENABLE_HMAC=1", "TC_ENABLE_KDF=1", "TC_ENABLE_SHA1=1",
        "TC_ENABLE_SHA224=1", "TC_ENABLE_SHA384=1", "TC_ENABLE_SHA512=1",
        "TC_ENABLE_DES=1", "TC_DES_ENABLE_CMAC=1", "TC_AES_ENABLE_CMAC=1",
    ], """
      struct TC_KBKDF_params p = {32, 1, 0};
      return TC_KBKDF_HMAC_SHA256_counter((TC_bytes){key, sizeof(key)}, &p, (TC_bytes){NULL, 0}, (TC_bytes){iv, sizeof(iv)}, (TC_buffer){out, sizeof(out)}) != TC_OK;
    """, "TC_KBKDF_HMAC_SHA256_counter"),
    "drbg_hmac_sha256": ([
        "TC_ENABLE_HMAC=1", "TC_ENABLE_DRBG=1", "TC_DRBG_ENABLE_HASH=0",
        "TC_DRBG_ENABLE_HMAC=1", "TC_DRBG_ENABLE_CTR=0",
    ], """
      static TC_DRBG drbg;
      const TC_bytes empty = {0, 0};
      TC_DRBG_config config = {TC_DRBG_HMAC, TC_HASH_SHA256, 0, 0, 0, 0, 0};
      TC_random_source source = {entropy, 0};
      if (TC_DRBG_instantiate(&drbg, &config, source, empty, empty) != TC_DRBG_OK) return 1;
      return TC_DRBG_generate(&drbg, out, sizeof(out), 0, empty) != TC_DRBG_OK;
    """, "TC_DRBG_generate"),
    # P-256 with byte limbs. Signing includes TC_ECDSA_SIGN_VERIFY, so its call
    # chain covers verification too.
    "ecdsa_p256": (["TC_ENABLE_EC=1", "TC_EC_ENABLE_P384=0"], """
      static TC_ECDSA_workspace workspace;
      static uint8_t public_key[65], signature[64];
      TC_EC_execution execution = {{entropy, 0}, 4, {UINT32_MAX}};
      TC_work_budget work = {UINT32_MAX};
      const TC_bytes point = {public_key, sizeof(public_key)};
      const TC_bytes digest = {key, sizeof(key)};
      if (TC_ECDSA_sign_digest(TC_EC_P256, (TC_bytes){key, sizeof(key)}, point, digest, (TC_buffer){signature, sizeof(signature)}, &workspace, &execution) != TC_EC_OK) return 1;
      out[0] = signature[0];
      return TC_ECDSA_verify_digest(TC_EC_P256, point, digest, (TC_bytes){signature, sizeof(signature)}, &workspace, &work) != TC_EC_OK;
    """, "TC_ECDSA_sign_digest"),
    # Plain PIV reads: SELECT, GET DATA and a VERIFY query on a SHORT link.
    # The link, the 261-byte command scratch and the response buffer are
    # application storage, recorded as piv_link_bytes and outside the stack.
    "apdu_piv_read": (["TC_ENABLE_APDU=1", "TC_ENABLE_TLV=1", "TC_ENABLE_PIV_COMMAND=1"], """
      static const uint8_t chuid[3] = {0x5f, 0xc1, 0x02};
      const TC_PIV_link_options options = {{TC_APDU_SHORT, 0, 8, 0, 0}, TC_PIV_CONTACT, 0};
      uint8_t scratch[TC_APDU_SHORT_COMMAND_MAX_BYTES], response[64];
      TC_PIV_link link;
      TC_PIV_application application;
      TC_PIV_data_object object;
      TC_PIV_reference_status status;
      TC_PIV_result result = TC_PIV_link_init(&link, (TC_APDU_transport){card, 0}, &options,
                                              (TC_buffer){scratch, sizeof(scratch)});
      if (result == TC_PIV_OK)
        result = TC_PIV_select(&link, TC_PIV_APPLICATION_PIV, 0, (TC_buffer){response, sizeof(response)}, &application);
      if (result == TC_PIV_OK)
        result = TC_PIV_get_data(&link, (TC_bytes){chuid, sizeof(chuid)}, (TC_buffer){response, sizeof(response)}, &object);
      if (result == TC_PIV_OK)
        result = TC_PIV_verify_status(&link, 0x80, &status);
      out[0] = response[0];
      TC_PIV_link_clear(&link);
      return result != TC_PIV_OK;
    """, ("TC_PIV_link_init", "TC_PIV_select", "TC_PIV_get_data", "TC_PIV_verify_status",
          "TC_PIV_link_clear")),
    # Secure messaging CS2 on the micro resource profile: key establishment,
    # link_secure and one protected GET DATA. The session, the workspace and
    # both scratch buffers are application storage.
    "piv_sm_cs2": ([
        "TC_RESOURCE_PROFILE=1", "TC_ENABLE_APDU=1", "TC_ENABLE_TLV=1", "TC_ENABLE_DER=1",
        "TC_ENABLE_PIV_COMMAND=1", "TC_ENABLE_PIV_SM=1", "TC_ENABLE_PIV_SM_APDU=1",
        "TC_ENABLE_PIV_CVC=1", "TC_ENABLE_EC=1", "TC_EC_ENABLE_P384=0", "TC_ENABLE_SSKDF=1",
        "TC_AES_ENABLE_DYNAMIC=1", "TC_PIV_SM_ENABLE_CS2=1", "TC_PIV_SM_ENABLE_CS7=0",
    ], """
      static const uint8_t chuid[3] = {0x5f, 0xc1, 0x02};
      TC_PIV_SM session;
      TC_PIV_SM_workspace workspace;
      uint8_t scratch[TC_APDU_SHORT_COMMAND_MAX_BYTES], sm_scratch[64], response[400];
      const TC_PIV_link_options options = {{TC_APDU_SHORT, 0, 16, 0, 0}, TC_PIV_CONTACT, 0};
      const uint8_t host[8] = {0};
      TC_PIV_link link;
      TC_PIV_SM_peer peer;
      TC_PIV_data_object object;
      TC_PIV_result result = TC_PIV_link_init(&link, (TC_APDU_transport){card, 0}, &options,
                                              (TC_buffer){scratch, sizeof(scratch)});
      if (result == TC_PIV_OK)
        result = TC_PIV_SM_key_request(&link, &session, TC_PIV_SM_CS2, host,
                                       (TC_random_source){entropy, 0},
                                       (TC_buffer){response, sizeof(response)}, &peer, &workspace);
      if (result == TC_PIV_OK && TC_PIV_SM_finish(&session, &peer, (TC_bytes){key, sizeof(key)}, &workspace) != TC_OK)
        result = TC_PIV_INVALID;
      if (result == TC_PIV_OK)
        result = TC_PIV_link_secure(&link, &workspace, (TC_buffer){sm_scratch, sizeof(sm_scratch)});
      if (result == TC_PIV_OK)
        result = TC_PIV_get_data(&link, (TC_bytes){chuid, sizeof(chuid)}, (TC_buffer){response, sizeof(response)}, &object);
      out[0] = response[0];
      TC_PIV_link_clear(&link);
      return result != TC_PIV_OK;
    """, ("TC_PIV_link_init", "TC_PIV_SM_key_request", "TC_PIV_SM_finish",
          "TC_PIV_link_secure", "TC_PIV_get_data", "TC_PIV_link_clear")),
}
# Public types whose AVR size a profile records, as {profile: {metric: type}}.
TYPE_SIZES = {"ecdsa_p256": {"ecdsa_workspace_bytes": "TC_ECDSA_workspace"},
              "apdu_piv_read": {"piv_link_bytes": "TC_PIV_link"},
              "piv_sm_cs2": {"sm_workspace_bytes": "TC_PIV_SM_workspace"}}
# Linked code of named translation units, as {profile: {metric: sources}}.
UNIT_FLASH = {"piv_sm_cs2": {"sm_framing_flash": ("piv_sm_apdu", "piv_sm_key_request")}}
# Functions whose indirect call reaches an application-supplied callback. The
# callback frame belongs to the application and is listed as excluded.
APPLICATION_CALLBACK_SITES = {
    "read_entropy": "TC_random_source entropy callback",
    "TC_ECDSA_sign_digest": "TC_random_source nonce callback",
    "transmit_step": "TC_APDU_transport transmit callback",
    # TC_TLV_walk and the stream reader call the caller's visitor. The PIV
    # command profile passes none.
    "emit": "TC_TLV_visit callback",
    "close_definite": "TC_TLV_visit callback",
    "feed": "TC_TLV_visit callback",
}
# PIV link functions that call the secure messaging table installed by
# TC_PIV_SM_key_request. Their indirect calls resolve to the table entries
# that survive --gc-sections. Without PIV_SM_APDU no table exists and the
# link never sets one.
# Each site calls one member, given as its position in the initializer.
PIV_SECURITY_SITES = {"tc_piv_link_transceive": 0, "tc_piv_link_unbind": 1}
BLOCK_CIPHER_CALLBACKS = {"tc_aes_block_encrypt", "tc_aes_block_decrypt",
                          "tc_des_block_encrypt", "tc_des_block_decrypt"}
# Mode and MAC cores that call the block cipher through a tc_block_cipher
# descriptor. Their indirect call resolves to BLOCK_CIPHER_CALLBACKS.
BLOCK_DESCRIPTOR_SITES = {"tc_mac_cbc_block", "tc_mac_derive_subkeys",
                          "tc_block_cbc_encrypt", "tc_block_cbc_decrypt",
                          "tc_block_ctr_crypt", "tc_block_ofb_crypt",
                          "tc_aes_kw_seal", "tc_aes_kw_open", "tc_aes_kw_wrap",
                          "tc_aes_kw_unwrap", "TC_AES_KW_wrap", "TC_AES_KW_unwrap",
                          "TC_AES_KWP_wrap", "TC_AES_KWP_unwrap"}
SOURCE = """
#include <tiny_crypto/tiny_crypto.h>
static uint8_t key[32], iv[16], out[32];
static volatile uint8_t sink;
static TC_status entropy(void* user, uint8_t* output, size_t length)
{ (void)user; while (length--) output[length] = key[length %% sizeof(key)]; return TC_OK; }
#if TC_ENABLE_APDU
static TC_status card(void* context, TC_bytes command, TC_buffer response, size_t* length)
{
  (void)context; (void)command;
  if (response.capacity < 2) return TC_ERROR;
  response.data[0] = 0x90; response.data[1] = 0x00; *length = 2; return TC_OK;
}
#endif
static int feature(void) { %s }
int main(void) { int status = feature(); sink = out[0]; return status; }
"""


def run(command):
    return subprocess.check_output(command, text=True, stderr=subprocess.STDOUT)


def normalize(name):
    return re.sub(r"\.(?:constprop|isra|part)(?:\.\d+)?", "", name)


def block_cipher_callbacks():
    """Keep the stack model in step with concrete block cipher descriptors.

    Each initializer lists block_size, key, encrypt and decrypt. The callbacks
    are the lowercase tc_ names after the key, or TC_ macros that name one.
    Test seams (tc_test_*) never link into the measured build."""
    sources = list((ROOT / "src").glob("*.c")) + list((ROOT / "src").glob("*.h"))
    texts = [source.read_text() for source in sources]
    aliases = {}
    for text in texts:
        for macro, target in re.findall(r"#define\s+(TC_\w+)\s+(tc_\w+)\s*$", text, re.M):
            if not target.startswith("tc_test_"):
                aliases[macro] = target
    found = set()
    for text in texts:
        for fields in re.findall(r"tc_block_cipher\s+\w+\s*=\s*\{([^}]*)\}", text):
            callbacks = fields.split(",", 2)[-1]
            found.update(re.findall(r"\btc_\w+", callbacks))
            found.update(aliases[name] for name in re.findall(r"\bTC_\w+", callbacks)
                         if name in aliases)
    if found != BLOCK_CIPHER_CALLBACKS:
        raise RuntimeError(f"Block cipher descriptor callbacks changed: {sorted(found)}")
    return found


def piv_security_callbacks(linked=None):
    """Functions named in tc_piv_link_security table initializers, as
    {member position: names}.

    With linked symbols given, only linked tables count, and a linked table
    whose member is missing from the link raises. A silent empty set would
    drop the secure messaging frames from the stack estimate."""
    found = {}
    for source in (ROOT / "src").glob("*.c"):
        for table, fields in re.findall(
                r"struct\s+tc_piv_link_security\s+(\w+)\s*=\s*\{([^}]*)\}",
                source.read_text()):
            if linked is not None and table not in linked:
                continue
            for position, field in enumerate(fields.split(",")):
                member = field.strip()
                if linked is not None and member not in linked:
                    raise RuntimeError(f"Unresolved PIV security table member: {table} {member}")
                found.setdefault(position, set()).add(member)
    return found


def hash_descriptor_callbacks():
    """Functions named in tc_hash_algorithm_info descriptors.

    hash_core.c calls them through the descriptor, while their addresses are
    taken in the per-algorithm files."""
    found = set()
    for source in (ROOT / "src").glob("*.c"):
        for block in re.findall(
                r"const\s+tc_hash_algorithm_info\s+\w+\s+TC_HASH_INFO_STORAGE\s*=\s*\{(.*?)\};",
                source.read_text(), re.S):
            found.update(re.findall(r"\b([a-z_][a-z0-9_]*)\b", block))
    if not found:
        raise RuntimeError("No hash descriptors found")
    return found


def type_sizes(directory, flags, types):
    """sizeof each public type under the profile flags, read from the emitted
    .size directive of a probe array."""
    sizes = {}
    for metric, name in types.items():
        source = directory / f"probe_{metric}.c"
        source.write_text("#include <tiny_crypto/tiny_crypto.h>\n"
                          f"unsigned char tc_probe[sizeof({name})] = {{1}};\n")
        assembly = source.with_suffix(".s")
        run([CC, *flags, "-S", str(source), "-o", str(assembly)])
        match = re.search(r"\.size\s+tc_probe,\s*(\d+)", assembly.read_text())
        if not match:
            raise RuntimeError("Missing size probe for " + name)
        sizes[metric] = int(match[1])
    return sizes


def unit_flash(directory, elf, units):
    """Linked .text bytes of the functions defined in each unit's object."""
    linked = {}
    for line in run([NM, "-S", str(elf)]).splitlines():
        fields = line.split()
        if len(fields) == 4 and fields[2] in "tT":
            linked[fields[3]] = int(fields[1], 16)
    total = 0
    for unit in units:
        for line in run([NM, "--defined-only", str(directory / (unit + ".o"))]).splitlines():
            fields = line.split()
            if len(fields) == 3 and fields[1] in "tT":
                total += linked.get(fields[2], 0)
    return total


def measure(directory, definitions, body, entry, types=None, units=None):
    flags = BASE + ["-D" + item for item in definitions]
    frames, edges, objects, unknown_indirect = {}, {}, [], []
    hash_core_sites = set()
    all_address_taken = set()
    for source in sorted((ROOT / "src").glob("*.c")):
        assembly = directory / (source.stem + ".s")
        run([CC, *flags, "-S", str(source), "-o", str(assembly)])
        for line in assembly.with_suffix(".su").read_text().splitlines():
            location, size, kind = line.split("\t")
            if kind not in ("static", "dynamic,bounded"):
                raise RuntimeError("Unbounded frame: " + line)
            name = normalize(location.rsplit(":", 1)[-1])
            frames[name] = max(frames.get(name, 0), int(size))
        text = assembly.read_text()
        address_taken = {normalize(x) for x in
                         re.findall(r"gs\(([A-Za-z_]\w*(?:\.\w+)*)\)", text)}
        all_address_taken.update(address_taken)
        current = None
        for line in text.splitlines():
            # Identical code folding aliases one function to another.
            match = re.match(r"\s*\.set\s+([A-Za-z_][\w.]*)\s*,\s*([A-Za-z_][\w.]*)\s*$", line)
            if match:
                alias, target = normalize(match[1]), normalize(match[2])
                frames.setdefault(alias, 0)
                edges.setdefault(alias, set()).add(target)
                continue
            match = re.search(r"\.type\s+([^,]+),\s*@function", line)
            if match:
                current = normalize(match[1])
                edges.setdefault(current, set())
            if current is None:
                continue
            match = re.match(r"\s*(?:call|rcall|jmp|rjmp)\s+([A-Za-z_]\w*(?:\.\w+)*)", line)
            if match:
                edges[current].add(normalize(match[1]))
            if re.match(r"\s*(?:icall|eicall|ijmp|eijmp)\s*$", line):
                if source.stem == "hash_core":
                    hash_core_sites.add(current)
                elif not address_taken:
                    unknown_indirect.append(current)
                edges[current].update(address_taken)
            if re.match(r"\s*\.size\s", line):
                current = None
        obj = assembly.with_suffix(".o")
        run([CC, "-mmcu=atmega328p", "-c", str(assembly), "-o", str(obj)])
        objects.append(str(obj))
    source = directory / "main.c"
    source.write_text(SOURCE % body)
    main_object = directory / "main.o"
    run([CC, *flags, "-c", str(source), "-o", str(main_object)])
    elf = directory / "profile.elf"
    run([CC, "-mmcu=atmega328p", str(main_object), *objects, "-Wl,--gc-sections",
         "-o", str(elf)])
    sections = {}
    for line in run([SIZE, "-A", str(elf)]).splitlines():
        match = re.match(r"(\.\w+)\s+(\d+)", line)
        if match:
            sections[match[1]] = int(match[2])
    if ".text" not in sections:
        raise RuntimeError("Missing linked .text section")
    unknown = set()
    # A descriptor call reaches only callbacks that survive --gc-sections.
    linked = {normalize(line.split()[-1]) for line in run([NM, str(elf)]).splitlines()
              if line.strip()}
    block_targets = block_cipher_callbacks() & all_address_taken & linked
    hash_targets = hash_descriptor_callbacks() & set(frames)
    security_targets = piv_security_callbacks(linked)
    for site in hash_core_sites:
        edges[site].update(hash_targets)

    def chain(name, active):
        if name in active:
            raise RuntimeError("Recursive stack path: " + name)
        if name not in frames:
            if name == entry or name.startswith(("TC_", "tc_")):
                raise RuntimeError("Missing project stack frame: " + name)
            unknown.add(name)
            return 0, []
        if name in APPLICATION_CALLBACK_SITES:
            unknown.add(APPLICATION_CALLBACK_SITES[name])
        elif (name in unknown_indirect and name not in BLOCK_DESCRIPTOR_SITES
              and name not in PIV_SECURITY_SITES):
            raise RuntimeError("Unresolved indirect call: " + name)
        if (name in BLOCK_DESCRIPTOR_SITES and name in unknown_indirect and name in linked
                and not block_targets):
            raise RuntimeError("Unresolved block cipher descriptor call: " + name)
        callees = set(edges.get(name, ()))
        if name in BLOCK_DESCRIPTOR_SITES:
            callees.update(block_targets)
        if name in PIV_SECURITY_SITES:
            callees.update(security_targets.get(PIV_SECURITY_SITES[name], ()))
        children = [chain(child, active | {name}) for child in sorted(callees)]
        size, path = max(children, default=(0, []), key=lambda item: item[0])
        return frames[name] + size, [name] + path

    # A profile with several public calls reports the deepest of them.
    entries = entry if isinstance(entry, tuple) else (entry,)
    stack, path = max((chain(name, set()) for name in entries), key=lambda item: item[0])
    report = {
        "flash": sections.get(".text", 0) + sections.get(".data", 0),
        "static_ram": sections.get(".data", 0) + sections.get(".bss", 0),
        "project_stack_estimate": stack,
        "stack_path": [{"function": name, "frame": frames[name]} for name in path],
        "excluded_external_callees": sorted(unknown),
        "kdf_workspace_frame": frames.get("tc_kdf_HMAC_SHA256"),
        "flags": [flag.replace(str(ROOT) + "/", "") for flag in flags],
    }
    report.update(type_sizes(directory, flags, types or {}))
    for metric, names in (units or {}).items():
        report[metric] = unit_flash(directory, elf, names)
    return report


def compiler_version(banner):
    """Version number from the first line of avr-gcc --version, or None."""
    match = re.search(r"(\d+\.\d+\.\d+)\s*$", banner)
    return match[1] if match else None


def check_budgets(report, budgets, stream=sys.stderr):
    """Fail when a measured metric exceeds its budget.

    The toolchain that produced the budgets is printed for comparison. A
    different avr-gcc version is reported and allowed."""
    print(f"budgets measured with avr-gcc {budgets.get('avr_gcc_version', 'unknown')}, "
          f"checking with avr-gcc {report.get('avr_gcc_version') or 'unknown'}", file=stream)
    for name, limits in budgets["profiles"].items():
        for metric, limit in limits.items():
            actual = report["profiles"][name][metric]
            if actual is None or actual > limit:
                raise SystemExit(f"{name} {metric}: {actual} exceeds {limit}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    banner = run([CC, "--version"]).splitlines()[0]
    report = {"compiler": banner, "avr_gcc_version": compiler_version(banner),
              "stack_scope": __doc__, "profiles": {}}
    with tempfile.TemporaryDirectory() as temporary:
        for name, (definitions, body, entry) in PROFILES.items():
            directory = Path(temporary) / name
            directory.mkdir()
            report["profiles"][name] = measure(directory, definitions, body, entry,
                                               TYPE_SIZES.get(name), UNIT_FLASH.get(name))
    if args.check:
        check_budgets(report, json.loads(args.check.read_text()))
    text = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
