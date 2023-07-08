# TODO's

## Notations and workflow

- Strikethrough - issue finished and moved to `CHANGELOG.md`.
- After finishing **Any time** issue must by moved to **Planned** and strikethroughed.
- Question mark `(?)` - issue needs further discussion.
- Issue identifier `[<link>]` - link to issue discussion (optional).

## Planned (by version)

### 0.7.13

- ~~Sign and verify messages [issue](https://github.com/PurpleBote/pboted/issues/16)~~
- ~~Beginning of JSON-RPC 2.0~~
- ~~Add bootstrap nodes in case of low count (<10)~~
- Make SAM params configurable
- Move Email send/recv to Identity as lymbda/bind -> remove EmailWorker
- DHT replication
- Check cross-identity-type sending
- Follow `freedesktop` specs:
  - `~/.pboted` to:
    - from `XDG_CONFIG_HOME` if set
    - `~/.config/pboted`
  - back compatible (copy old to new) (?)
- OpenSSL 3.0.0 support
- Verify memory leak (See https://github.com/PurpleI2P/i2pd/commit/55b2f2c625ae3b7de2d6f20716c908bba801c370)

### 0.7.14

- Fix Bote DEL logic:
  - keep removed nodes and peers in memory to prevent new addition
  - Index del with DA like Email del
  - if store req return with del - sent del to other
- KadDHT from libi2pd + make it Templated
- Boost removed (?) [issue](https://github.com/PurpleBote/pboted/issues/28)
- Drop C++11 and C++14, only C++17 and above (?)
- SMTP/POP3 restart on error
- HashCash generate/verify
- Refactoring (atomic, byte, Class::ptr)
  - Extern to objects + restart on error
  - DHTStorage to Fylesystem
  - Context to IdentityStorage
  - CID to crypto
  - Remove exceptions and try/catch

### 0.8.0

- Control full support (for pbotectl) JSON-RPC 2.0
  - Rename Control (?)
- STARTTLS (SAM, SMTP, Control, etc.) (?)
- SMTP full support - direct mail (bdsmail, mail.i2p)
  - indi key
  - SAM stream
  - Subdirs by identity (incomplete, sent, inbox, outbox)
  - think about mail2bote bridge (just SMTP?) - THAT'S IT (?)
- Maildir support
- Auth for SMTP, POP3, Control
- Identity name validation for local-part (to create email directory)
- Custom per identity/user email folders (!)
- BoteV5 full support
  - Relay logic (Sending and receiving via relays, similar to Mixmaster)(!)
  - Multiple versions wrappers/impl's - how (?)
    - The goal is to achieve ease of protocol upgrade
- Sending email anonymously (with transient keys)(!)
- GNUTLS support (?)
- Java Properties to JSON for identities file (?)

### 0.8.1

- Network error handling and reconnecting - Add functionality to handle disconnection
  - re-create UDP sockets
  - re-create SAM session

### 0.8.2

- Local files encryption (addressbook, identities, etc.)
- Clean remotest nodes, we need only closest
- vector to sets for nodes/peers (?)

### 0.8.3

- IMAP via Dovecot or built-in (?)
- SAMv3.2 (3.3)

### 0.9.0

- IPv6 support 
- Ban peer/node (WRONG_PROTO_VER - for future)
- NTRUEncrypt support [issue](https://github.com/PurpleBote/pboted/issues/31)

### 0.9.1

- Remove/fix ALL ToDo's from code (?)

### 1.0.0

- BoteV6 full support

## Any time

- Bundle with pbotectl (?) [issue](http://purplebote.i2p/topics/7)
- Docs (INSTALL, man, etc.)
- RFC styled docs for I2P/Bote
- Platforms build/support:
  - OpenWrt
  - FreeBSD
  - Arch/Manjaro
  - MacOS
- OS repositories
  - Debian/Devuan/Raspbian/Ubuntu/Kali
  - Arch/Manjaro + AUR
  - OpenWRT
  - FreeBSD/OpenBSD
  - Homebrew
