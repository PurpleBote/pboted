# Message formatter

Simple script for fomatting the message for further sending through **pboted**.   
Also, compatible with Java I2P-Bote decrypted identities file.

Once the script has been completed, it will produce a formatted message.
It will need to be placed to directory "outbox" in **pboted** directory.

## Prepare

For the script to work, version Python is required at least 3.8     
Before getting started, you will need to install the dependencies for each script:

```
pip3 install -r requirements.txt
```

## Parameters

- `-v` `--version` - Print version and exit
- `-s` `--subject` - Message subject
- `-m` `--messagepath` - Path to message TXT file
- `-i` `--identity` - Bote identity name
- `-f` `--identityfile` - Bote identities file
- `-r` `--recipient` - Recipient name
- `-a` `--recipientidentity` - Base64 encoded Bote identity

## Example

```
./message_formatter.py -s "Secret message to Alice" -m /path/to/message.txt -i john_doe -f /path/to/identities.txt -r alice -a "pXEPJzP7ElhKbdrPtzoVLxWaexPmNeboahFP5PbBikzhSGGI1cjCY5wk3NsMHCn2zBmWQ95z9k4DSBly7vmvPB" > /home/john/.pboted/outbox/new_message.txt
```
