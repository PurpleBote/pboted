# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.13] - 2023-05-01

### Added

- Signing and verification of MIME messages
- Adjusted Control protocol to JSON-RPC 2.0 format
- DHT replication
- OpenSSL 3.0.0 support

### Changed

- Disable Control by befault
- Load bootstrap nodes in case of low count of usual nodes (<10)
- Email send/recv to Identity as lymbda/bind = remove EmailWorker
- Userspace conf dir to `~/.config/pboted` with back compatible (copy old to new)
- Autocrypt header added to whitelist

### Deprecated

- I2P/Bote V4 parts will be removed on release 0.8.0

## [0.7.12] - 2022-11-28

### Added

- Windows support
- Local DHT cleanup on startup

### Changed

- Replaced `boost::filesystem` with `std::filesystem`
- Reduced timeouts for faster processing
- Cleanup optimized
- Emails and Index cleanup moved to new email packets processing
- Incomplete task only try to restore mails from parts
- Sent Email remove request only after Index for this Email removed
- Shutdown optimization

### Fixed

- SMTP/POP3: High CPU usage
- SMTP: Message-ID setup
- Blocking on accept /receive
- Index cleanup logic
- Crash on new packet receive to already removed batch
- Logging of signals

## [0.7.11] - 2022-09-19

### Added

- Email delivery confirmation
- Basic support for big messages (spliting huge email to ~30KiB packets)
- Clean unreachable peers and nodes (not responde more than 1 week by default)

### Changed

- Email retrieving optimized
- Reduced waiting time for responses
- Files not needed in project were removed from `libi2pd` and `i2psam`
- Initialization and shutdown optimizations

### Fixed

- Bug with deadlock in POP3 RETR
- Bug with comparations of packet types
- Bug with Message-ID assignment

## [0.7.10] - 2021-07-12

### Added

- Support for SECP521R1
- Support for X25519
- SAM session error handling and reconnecting
- Path parameter to store/load SAM destination key
- Cleaner for old index entries (remove old packets only if we have less than 10 MiB of free storage space)
- SMTP/POP3: Changed default ports

### Changed

- Datagram receiving optimization
- Updated `i2pd` and `i2psam`
- Kilo and etc. formatted to Kibi and etc.
- Optimized filling for MIME fields FROM, SENDER, and TO
- Saving email to source outbox file after assigning an Message-ID to prevent re-sending with different Message-ID
- Simplified search for closest nodes
- Reworked calculation of the remaining responses
- Changed seeding of the random number generator
- Packets parsing optimization

### Fixed

- Save/remove logic for Index and Email packets
- Issue with index updating
- Issue with delete requests parsing
- Filesystem deadlock
- Leak in active batches
- Daemon initialization
- Some logs typos

## [0.7.9] - 2022-06-09

### Fixed

- Filename conversion
- Overflow in uptime and traffic
- Some logs typos

## [0.7.8] - 2022-02-20

### Changed

- Updated used OpenSSL functions with `_EVP`

### Fixed

- Message-ID not reset if exist
- Delete Auth not reset
- Email Hash verification
- Selection for compression/decompression algorithm
- Alias search for FROM and TO fields

## [0.7.7] - 2022-02-03

### Added

- SMTP/POP3: Reworked session logic
- SMTP/POP3: Now both servers process connections sequentially without multithreading
- SMTP/POP3: Updated command processing logic

### Changed

- Network improvements and optimizations
- Improved application initialization
- Peer min and max metric
- The node blocking mechanism has been redesigned

### Fixed

- SMTP/POP3: Added the 1 second delay to the loop as a workaround (the reason for the high load has been eliminated). Need to rework the solution with condition_variable (as a true way)
- Samples rollback if have no responses from peers
- Crash on remove iterated file
- Output of remain responses
- Node blocking logic
- Adding peer reachability
- Bug in MessageID conversion

## [0.7.6] - 2022-01-22

### Added

- Control interface

### Changed

- Updated `i2psam` and `i2pd` submodules
- Minor optimizations

### Fixed

- Crash when receiving/sending packets
- Bug with not closing socket

## [0.7.5] - 2021-12-13

### Added

- ZLIB support

### Changed

- Email Identity refactoring

### Fixed

- Message-ID usage
- Saving of Inbox messages

## [0.7.4] - 2021-12-02

### Added

- Removing of old packets
- Logic for processing duplicated data

### Changed

- Packet handler optimization
- POP3: response formatting optimization
- Optimization of arrays

### Fixed

- Delay in the loop to reduce the frequency of connection retries and not litter the log with errors
- Logic for correct Index Packet processing
- Memory leak in IVEC
- Import for `libi2pd`
- Bug with padding in AES decryption

## [0.7.3] - 2021-11-19

### Added

- GitHub Actions CI build
- Disk space usage limit config parameter

### Changed

- Check store response status and do not move message to sent in case of failure
- Updated default config file

### Removed

- Unused 7-zip SDK code

### Fixed

- Fixed `checkOutbox()` for non-alias addresses
- Fixed response in case if disk usage limit reached
- POP3 client able to remove email after fetch
- README.md fixes and minor spelling

## [0.7.2] - 2021-10-25

### Added

- Replacement of alias for SMTP-created mails

## [0.7.1] - 2021-10-23

### Added

- POP3 server
- SMTP server

## [0.7.0] - 2021-10-19

### Added

- Email Delete request for retrieved emails
- Index Delete request for retrieved Index packets

### Changed

- Run CheckEmailTask with one identity without loop

## [0.6.0] - 2021-10-17

### Added

- Handlee for bad requests

### Changed

- After sending, email will be moved to sent with metadata

### Fixed

- Relay Peers reachability setup

## [0.5.0] - 2021-09-21

### Added

- Full DHT node functionality

### Changed

- Review Relay Peers worker

## [0.4.0] - 2021-09-21

### Added

- Encrypting and sending MIME message

## [0.3.0] - 2021-06-19

### Added

- DHT find
- Parse email identity from file
- Increasing and decreasing peer metrics
- Workaround for received peers and nodes - add to lists as DSA
- LZMA support
- Receiving, decrypting and decompressing of MIME message 

### Changed

- Remove `ClosestNodesLookupTask` and re-make it as function
- Move `random_cid ()` to context
- Change log format

### Fixed

- Network bug with trimming packages
- Peer creation with sign key type enumeration
- Identity loading

## [0.2.0] - 2020-10-20

### Added

- Peers and DHT nodes interaction
- Complete relay peers discovery task

## [0.1.0] - 2020-05-21

### Added

- Basic networking done
- SAMv3 session creation
