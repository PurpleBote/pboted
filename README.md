[![GitHub release](https://img.shields.io/github/release/polistern/pboted.svg?label=latest%20release)](https://github.com/polistern/pboted/releases/latest)
[![License](https://img.shields.io/github/license/polistern/pboted.svg)](https://github.com/polistern/pboted/blob/master/LICENSE)
[![Documentation Status](https://readthedocs.org/projects/pboted/badge/?version=latest)](http://pboted.readthedocs.io/?badge=latest)

# pboted

pboted (Plus Bote Daemon) - is a standalone C++ implementation of I2P-Bote protocol.

I2P-Bote is a server-less encrypted KademliaDHT-based email protocol.  
You can find more details in the [documentation](https://pboted.readthedocs.io/en/latest/bote/v5/version5/)([I2P](http://polistern.i2p/pbote/bote/v5/version5/)).

Interaction with the I2P network occurs through the [SAMv3](https://geti2p.net/ru/docs/api/samv3) interface.  
Tested with [i2pd](https://github.com/PurpleI2P/i2pd) and [Java I2P](https://github.com/i2p/i2p.i2p).

## Alpha

Please note that **pboted** version **0.7.X** is still in **alpha**.  
During this period, there may be significant changes in the application.

Transition to **beta** planned in version **0.9.X**

## Features

- Sending and receiving emails
- Support for short recipient names (alias)
- [End-to-End encryption](https://pboted.readthedocs.io/en/latest/bote/v5/cryptography/)([I2P](http://polistern.i2p/pbote/bote/v5/cryptography/))
- Runnable as daemon
- [CLI utility](https://github.com/polistern/pbotectl) (work in progress)
- SMTP / POP3 support (tested with [Mozilla Thunderbird](https://www.thunderbird.net/en-US/))
- Delivery confirmation

### Planned Features

- Custom per identity/user email folders
- Sending email anonymously
- Sending and receiving via relays, similar to Mixmaster
- Interfaces for interaction with third-party applications (IMAP, etc.)

## Resources

- [Documentation](https://pboted.readthedocs.io/en/latest/)([I2P](http://polistern.i2p/pbote/))
- [Tickets/Issues](https://github.com/polistern/pboted/issues)

## Installing

You can fetch precompiled packages and binaries on [release](https://github.com/polistern/pboted/releases/latest) page.  
Please see [documentation](https://pboted.readthedocs.io/en/latest/user-guide/install/)([I2P](http://polistern.i2p/pbote/user-guide/install/)) for more info.

### Supported systems

- GNU/Linux - [![Build](https://github.com/polistern/pboted/actions/workflows/build.yml/badge.svg)](https://github.com/polistern/pboted/actions/workflows/build.yml)
  - Debian / Ubuntu - [![Build DEB](https://github.com/polistern/pboted/actions/workflows/build-deb.yml/badge.svg)](https://github.com/polistern/pboted/actions/workflows/build-deb.yml)
  - CentOS / Fedora
<!---
- [![Build RPM](https://github.com/polistern/pboted/actions/workflows/build-rpm.yml/badge.svg)](https://github.com/polistern/pboted/actions/workflows/build-rpm.yml)
--->

## Building

See [documentation](https://pboted.readthedocs.io/en/latest/building/requirements/)([I2P](http://polistern.i2p/pbote/user-guide/install/#building-from-source)) for how to build **pboted** from source.

## Usage

See [documentation](https://pboted.readthedocs.io/en/latest/user-guide/install/#building-from-source)([I2P](http://polistern.i2p/pbote/user-guide/usage/)) and [example config file](https://github.com/polistern/pboted/blob/master/contrib/pboted.conf).

## Donations

- **XMR**: `85P3aEXrYMn1YxnQaZSBWy6Ur6j9PVRxmCd3Ey1UanKAdKnhd2iYNdrEhNJ2JeUdcC8otSHogRTnydn4aMh8DwbSMs4N13Z`

## License

This project is licensed under the BSD 3-clause license, which can be found in the file LICENSE in the root of the project source code.

## Special thanks

- [orignal](https://github.com/orignal) - for mentoring
- [R4SAS](https://github.com/r4sas) - for the help at the start
