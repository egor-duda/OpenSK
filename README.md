# <img alt="OpenSK logo" src="docs/img/OpenSK.svg" width="200px">

![markdownlint](https://github.com/google/OpenSK/workflows/markdownlint/badge.svg?branch=develop)
![pylint](https://github.com/google/OpenSK/workflows/pylint/badge.svg?branch=develop)
![Cargo check](https://github.com/google/OpenSK/workflows/Cargo%20check/badge.svg?branch=develop)
![Cargo format](https://github.com/google/OpenSK/workflows/Cargo%20format/badge.svg?branch=develop)
[![Coverage Status](https://coveralls.io/repos/github/google/OpenSK/badge.svg?branch=develop)](https://coveralls.io/github/google/OpenSK?branch=develop)

## OpenSK

This repository contains a Rust implementation of a
[FIDO2](https://fidoalliance.org/fido2/) authenticator.
We developed OpenSK as a [Tock OS](https://tockos.org) application.

We intend to bring a full open source experience to security keys, from
application to operating system. You can even 3D print your own open source
enclosure!
You can see OpenSK in action in this
[video on YouTube](https://www.youtube.com/watch?v=klEozvpw0xg)!

You are viewing the branch for developers. New features are developed here
before they are stabilized. If you instead want to use the FIDO certified
firmware, please go back to the
[stable branch](https://github.com/google/OpenSK).

### FIDO2

The develop branch implements the
[CTAP2.1 specification](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html).
This branch is not FIDO certified. The implementation is backwards compatible
to CTAP2.0. Additionally, OpenSK supports U2F, and non-discoverable credentials
created with either protocol are compatible with the other.

### :warning: Disclaimer

This project is **proof-of-concept and a research platform**. It is **NOT**
meant for a daily usage. It comes with a few limitations:

*   This branch is under development, and therefore less rigorously tested than the stable branch.
*   The cryptography implementations are not resistent against side-channel attacks.

We're still in the process of integrating the
[ARM&reg; CryptoCell-310](https://developer.arm.com/ip-products/security-ip/cryptocell-300-family)
embedded in the
[Nordic nRF52840 chip](https://infocenter.nordicsemi.com/index.jsp?topic=%2Fps_nrf52840%2Fcryptocell.html)
to enable hardware-accelerated cryptography. Our placeholder implementations of required
cryptography algorithms (ECDSA, ECC secp256r1, HMAC-SHA256 and AES256) in Rust are research-quality
code. They haven't been reviewed and don't provide constant-time guarantees.
  
## Hardware

You will need one the following supported boards:

*   [Nordic nRF52840-DK](https://www.nordicsemi.com/Software-and-Tools/Development-Kits/nRF52840-DK)
    development kit. This board is more convenient for development and debug
    scenarios as the JTAG probe is already on the board.
*   [Nordic nRF52840 Dongle](https://www.nordicsemi.com/Software-and-tools/Development-Kits/nRF52840-Dongle)
    to have a more practical form factor.
*   [Makerdiary nRF52840-MDK USB dongle](https://wiki.makerdiary.com/nrf52840-mdk/).
*   [Feitian OpenSK dongle](https://feitiantech.github.io/OpenSK_USB/).

## Installation

To install OpenSK,
1.  follow the [general setup steps](docs/install.md),
1.  then continue with the instructions for your specific hardware:
	* [Nordic nRF52840-DK](docs/boards/nrf52840dk.md)
	* [Nordic nRF52840 Dongle](docs/boards/nrf52840_dongle.md)
	* [Makerdiary nRF52840-MDK USB dongle](docs/boards/nrf52840_mdk.md)
	* [Feitian OpenSK dongle](docs/boards/nrf52840_feitian.md)

To test whether the installation was successful, visit a
[demo website](https://webauthn.io/) and try to register and login.
Please check our [Troubleshooting and Debugging](docs/debugging.md) section if you
have problems with the installation process or during development. To find out what
else you can do with your OpenSK, see [Customization](docs/customization.md).

## Contributing

See [Contributing.md](docs/contributing.md).

## Reporting a Vulnerability

See [SECURITY.md](SECURITY.md).
