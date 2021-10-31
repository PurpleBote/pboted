# pboted

pboted (Plus Bote Daemon) - is a standalone C++ implementation of I2P-Bote (server-less Kademlia DHT-based email) protocol.   
Interaction with the I2P network occurs through the SAMv3 interface (tested with i2pd and Java I2P).

## Features

- Sending and receiving emails
- Basic support for short recipient names
- Elliptic Curve encryption (ECDH-256/ECDSA-256/AES-256/SHA-256)
- Runnable as daemon or as user service
- SMTP / POP3 (basic support, work in progress)

### Planned Features

- Custom per identity/user email folders
- Sending email anonymously
- Delivery confirmation
- Sending and receiving via relays, similar to Mixmaster
- CLI interface and tools
- Interfaces for interaction with third-party applications (IMAP, etc.)

### Protocol version 5

At the moment, PeerList packets of 5th version have been implemented to support current types of I2P destination.   
PeerList packets of 4th version are supported, older Java nodes respond but do not send requests due to protocol restrictions at DSA I2P destinations.
You can see the implementation details in `docs/techdoc_v5 (draft).txt` file.

Proposals for improving the 5th version of the protocol are accepted for consideration.

## Build process

### The pboted needs MIME library - mimetic 

_Will be added to build process later._

For now you need to build this library before starting build pboted

Sources: [link](http://www.codesink.org/mimetic_mime_library.html)   
Tested with version: 0.9.8

- Download archive with sources
- Go to source directory
- Build and install library:

```
./configure
make
sudo make install
```

- If you don't like to use raw `make install` (like me) you can use `checkinstall`:

```
apt install checkinstall
./configure
make
sudo checkinstall --pkgname=mimetic --pkgversion=0.9.8
```

### For Debian/Ubuntu:

_Tested with Debian 10 and Ubuntu 20.04._

- Install development libraries:

```
apt install git cmake build-essential libboost-filesystem-dev libboost-system-dev libssl-dev libboost-program-options-dev libboost-date-time-dev libboost-thread-dev zlib1g-dev
```

- Clone repository:

```
git clone https://github.com/polistern/pboted.git
```

- Build:

```
cd pboted
cmake -DCMAKE_BUILD_TYPE=Release
make
```

- Put binary to `/usr/sbin/`

```
sudo mv pboted /usr/sbin/pboted
```

## Configuration

### The pboted needs I2P router

- Install and run i2pd
- Enable SAM API in i2pd. Edit in i2pd.conf:

```
[sam]
enabled = true
```

- Restart i2pd   
- Local TCP port 7656 and UDP port 7655 should be available

### User service configuration

- Copy example config from `contrib/pboted.conf` to `~/.pboted/pboted.conf`:

```
cp contrib/pboted.conf ~/.pboted/pboted.conf`
```

- Edit the config to suit your needs. The file is well documented, comments will help you.
- Now you can run application:

```
./pboted --conf ~/.pboted/pboted.conf
```

### Unix daemon configuration [recommended]

- Create `/etc/pboted` directory:

```
mkdir /etc/pboted
```

- Copy example config from `contrib/pboted.conf` to `~/.pboted/pboted.conf`:

```
cp contrib/pboted.conf /etc/pboted/pboted.conf`
```

- Edit the config to suit your needs. The file is well documented, comments will help you.
- Create user, data and logs directories:

```
useradd pboted -r -s /usr/sbin/nologin
mkdir /var/lib/pboted
chown -R pboted: /var/lib/pboted
mkdir /var/log/pboted
chown -R pboted: /var/log/pboted
```

- Copy example systemd service from `contrib/pboted.service` to `/lib/systemd/system/pboted.service`:

```
cp contrib/pboted.service /lib/systemd/system/pboted.service`
```

- Reload daemons configuration and start unit:

```
systemctl daemon-reload
systemctl start pboted.service
```

- Now you can see in log files that all works. Also, you can see the status of the SAM session in the I2P Router console.

## Usage

You may need the utilities from the `utils` directory to work with **pboted**.   
In the future, their list will grow.   
There are plans to transfer all means for interaction into a separate CLI utility.

You can only continue to use your Java I2P-Bote identities if:

- your address is created using the ECDH-256/ECDSA-256/AES-256/SHA-256 algorithm (others are not supported yet)
- identities file is not encrypted (encrypted files are not supported yet)

### Sending email

#### SMTP

To be able to send email through SMTP you need to:

- Fill [smtp] section in configuration file:

```
[smtp]
enabled = true
address = 127.0.0.1
port = 25
```

- Restart the **pboted** to apply the settings
- After loading, you be able to connect to the specified SMTP port manually or with your mail client

#### Via `outbox` directory 

- Prepare plain test message
- Format it with `message_formatter`
- Put result file to `outbox` directory in pboted working directory
- pboted will automatically check `outbox` and send email
- After sending email file will be moved to `sent` directory

### Receiving email

After starting with a generated identity the application will begin its normal job of searching for mail.  
If mail for identity are found, they will be placed in the `inbox` directory.

#### POP3

To be able to receive email through POP3 you need to:

- Fill [pop3] section in configuration file:

```
[pop3]
enabled = true
address = 127.0.0.1
port = 110
```

- Restart the **pboted** to apply the settings
- After loading, you be able to connect to the specified POP3 port manually or with your mail client.

## Donations

- **BTC**: `bc1qans7ukm5t62mjcuhl3rpzxml05etyljhjt7w76`
- **DASH**: `XfeBg9i7MwbW2X1y1HpgHZ4sB7jqxhSfta`
- **GST**: `GatPEoV4uK2z1mgbph577Tv1WavrL5vmSE`
- **XMR**: `85P3aEXrYMn1YxnQaZSBWy6Ur6j9PVRxmCd3Ey1UanKAdKnhd2iYNdrEhNJ2JeUdcC8otSHogRTnydn4aMh8DwbSMs4N13Z`

## License

This project is licensed under the BSD 3-clause license, which can be found in the file LICENSE in the root of the project source code.

## Special thanks

* [orignal](https://github.com/orignal) - as mentor
