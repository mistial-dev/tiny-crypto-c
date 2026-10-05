<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# ESP32-P4 and PIV targets

The ESP-IDF port builds the library as a component. Select an [application target](targets.md)
such as `piv` or `twic` with `TINY_CRYPTO_TARGET`, and any resource profile.

## Platform features

Application image hashing uses a vendored bootloader-support component, pinned to ESP-IDF 5.5,
with a library SHA-256/384/512 adapter. The separate bootloader keeps the original IDF component
([vendor provenance](../ports/esp-idf/vendor/bootloader_support/PROVENANCE.md)). Application builds
reject mbedTLS dependencies.

The component enables SHA-256, SHA-384 and SHA-512 for the image hash. Signed-update configuration
adds RSA, or EC with P-192 and P-256, for Secure Boot v2 verification with RSA-3072 PSS or
P-192/P-256 ECDSA. These platform features apply with or without a target. `AUTO` selects them,
and an explicit `OFF` fails configuration.

The application supplies access policy, trust anchors and revocation data. The native X.509
signature provider uses [ECDSA](ec.md) and [RSA](rsa.md) verification.
[Path validation](x509-path.md) and [path construction](x509-store.md) work from
application-supplied certificates and anchors, and revocation has its own API. Verify the card's
CVC chain before passing its key to secure messaging.

## Build

Install ESP-IDF with ESP32-P4 support and activate it with `export.sh`. From the repository root:

```sh
idf.py -C examples/esp32-p4 -B /tmp/tiny-crypto-esp32p4-piv \
  -DTINY_CRYPTO_TARGET=piv build
idf.py -C examples/esp32-p4 -B /tmp/tiny-crypto-esp32p4-twic \
  -DTINY_CRYPTO_TARGET=twic build
```

The example defaults to `mini`, an 8 KiB main-task stack and no PSRAM. Its 2 MiB flash setting is
a build default. Set the board's flash size and partition table in `menuconfig` before flashing.
The configuration stays in the selected build directory.

```sh
idf.py -C examples/esp32-p4 -B /tmp/tiny-crypto-esp32p4-piv menuconfig
idf.py -C examples/esp32-p4 -B /tmp/tiny-crypto-esp32p4-piv size
idf.py -C examples/esp32-p4 -B /tmp/tiny-crypto-esp32p4-piv size-components
idf.py -C examples/esp32-p4 -B /tmp/tiny-crypto-esp32p4-piv -p PORT flash monitor
```

On a board, the example times SHA-384 and P-256/P-384 public-key generation as single operations
and prints free internal heap and unused main-task stack. The linker drops unused library
functions. ESP-IDF's size percentages use linker regions and configured flash, which can differ
from the board's capacity.

## Signed updates

For a signed-update build without hardware secure boot, use a fresh build directory and one of
the supplied configuration fragments:

```sh
idf.py -C examples/esp32-p4 -B /tmp/tiny-crypto-esp32p4-signed-rsa \
  '-DSDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.signed-rsa' build
idf.py -C examples/esp32-p4 -B /tmp/tiny-crypto-esp32p4-signed-ecdsa \
  '-DSDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.signed-ecdsa' build
```

Defaults apply only to settings absent from the build directory's `sdkconfig`. Select signed
applications and the RSA or ECDSA-v2 scheme in `menuconfig`. The images need external signing
before installation. Hardware secure boot and key provisioning are separate steps.

The application override keeps IDF's signature-block checks and trusted-key selection. Without
hardware secure boot, IDF takes the trusted key from the running application's signature block.
With secure boot, it uses the eFuse key digests. Provisioning and revocation stay IDF operations.

The example leaves out update download and installation. Signed-update builds link the verifier,
`esp_ota_end` and `esp_ota_set_boot_partition` to check the verification and boot-selection path.
An application finishes and validates the image with `esp_ota_end`, then selects it with
`esp_ota_set_boot_partition`.

Downgrade protection needs rollback configuration as well. `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`
handles fallback from an unconfirmed application, and `CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK`
enforces its secure version. The example defaults disable both. Configure an OTA partition table
and test confirmation and recovery before deploying either. Secure-version advancement and
secure-boot provisioning can change eFuses irreversibly, so validate on development hardware
first.

Host [signed-image and policy tests](testing.md#esp-idf-signed-image-tests) exercise RSA and
ECDSA. Reboot, interrupted-write and eFuse behavior need on-device testing.

## Use as a component

Add the component directories to `EXTRA_COMPONENT_DIRS` before including ESP-IDF's
`project.cmake`:

```cmake
list(APPEND EXTRA_COMPONENT_DIRS "/path/to/tiny-crypto-c/ports/esp-idf/tiny-crypto-c")
list(APPEND EXTRA_COMPONENT_DIRS "/path/to/tiny-crypto-c/ports/esp-idf/vendor/bootloader_support")
set(TINY_CRYPTO_TARGET piv CACHE STRING "Application target")
set(TINY_CRYPTO_RESOURCE_PROFILE mini CACHE STRING "Resource profile")
```

Your component declares `REQUIRES tiny-crypto-c`. The adapter uses the normal CMake source and
feature selection, so public headers and library objects share one configuration. The core has no
ESP-IDF dependency or hardware crypto backend. See the
[ESP-IDF build guide](https://docs.espressif.com/projects/esp-idf/en/v5.5.1/esp32p4/api-guides/build-system.html)
for component integration and [Running the tests](testing.md) for host suites.
