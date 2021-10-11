# Bote identity generator

Simple script to generate Bote identity for use in **pboted**.   
The script reads the current contents of identities file, generates new identity and write to the same file.

Also, compatible with Java I2P-Bote decrypted identities file.

## Prepare

For the script to work, version Python is required at least 3.8
Before getting started, you will need to install the dependencies for each script:

```
pip3 install -r requirements.txt
```

## Parameters

- `-v` `--version` - Print version and exit
- `-n` `--name` - The public name of the identity, included in emails
- `-a` `--algorithm` - Encryption and signature algorithm. For now only 2 (ECDSA 256). Default: `2`
- `-p` `--picture` - Path to image file
- `-d` `--description` - Description of the identity, only displayed locally.
- `-f` `--filename` - Full path to current identities file. Default: identities.txt

## Example

Minimal usage:
```
./create_identity.py -n john_doe -a 2
```

Full case:
```
./create_identity.py -n john_doe -a 2 -p /path/to/image.png -d "John main identity" -f /path/to/identities.txt
```

