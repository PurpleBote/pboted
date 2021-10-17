# pboted

pboted (Plus Bote Daemon) - is a C++ implementation of I2P-Bote protocol.      
I2P-Bote - server-less Kademlia(DHT)-based e-mail application.  
Interaction with the I2P network occurs through the SAMv3 interface (Java I2P and i2pd).

## Features

For now implemented only basic functionality

- Sending and receiving emails
- Storing DHT packets
- Elliptic Curve encryption (ECDH-256/ECDSA-256/AES-256/SHA-256)
- Runnable as daemon or as user service

### Planned Features

- CLI interface
- Interfaces for interaction with third-party applications (SMTP, IMAP, POP3, etc.)

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
cmake .
make
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
- Local TCP port 7656 should be available

### User service configuration

- Copy example config from `contib/pboted.conf` to `~/.pboted/pboted.conf`:

```
cp contib/pboted.conf ~/.pboted/pboted.conf`
```

- Edit the config to suit your needs. The file is well documented, comments will help you.
- Now you can run application:

```
./pboted --conf ~/.pboted/pboted.conf
```

### Unix daemon configuration

- Create `/etc/pboted` directory:

```
mkdir /etc/pboted
```

- Copy example config from `contib/pboted.conf` to `~/.pboted/pboted.conf`:

```
cp contib/pboted.conf /etc/pboted/pboted.conf`
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

- Copy example systemd service from `contib/pboted.service` to `/lib/systemd/system/pboted.service`:

```
cp contib/pboted.service /lib/systemd/system/pboted.service`
```

- Reload daemons configuration and start unit:

```
systemctl daemon-reload
systemctl start pboted.service
```

- Now you can see in log files that all works

## Usage

You may need the utilities from the `utils` directory to work with **pboted**.   
In the future, their list will grow.   
There are plans to transfer all means for interaction into a separate CLI utility.

You can only continue to use your Java I2P-Bote identities if:

- your address is created using the ECDH-256/ECDSA-256/AES-256/SHA-256 algorithm (others are not supported yet)
- identities file is not encrypted (encrypted files are not supported yet)

### Sending email

- Prepare plain test message
- Format it with `message_formatter`
- Put result file to `outbox` directory in pboted working directory
- pboted will automatically check `outbox` and send email
- After sending email file will be moved to `sent` directory

### Receiving email

Just start pboted with generated identity and check `inbox` in working directory. 

## Donations

- **BTC**: `bc1qans7ukm5t62mjcuhl3rpzxml05etyljhjt7w76`
- **DASH**: `XfeBg9i7MwbW2X1y1HpgHZ4sB7jqxhSfta`
- **GST**: `GatPEoV4uK2z1mgbph577Tv1WavrL5vmSE`
- **XMR**: `85P3aEXrYMn1YxnQaZSBWy6Ur6j9PVRxmCd3Ey1UanKAdKnhd2iYNdrEhNJ2JeUdcC8otSHogRTnydn4aMh8DwbSMs4N13Z`
- **ZEC**: `zs1mex948e8ucjsgu5p4r9t2zmd9pau53gr9kz0zw8vnl6mkuq373egeaese7t73l9rnsp567r3njv`

## License

This project is licensed under the BSD 3-clause license, which can be found in the file LICENSE in the root of the project source code.

## Special thanks

* [orignal](https://github.com/orignal) - as mentor
