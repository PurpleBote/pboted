#!/usr/bin/env python3

__title__ = 'Bote Message Formatter'
__version__ = "1.0.0"
__author__ = "polistern"
__maintainer__ = "polistern"
__status__ = "Production"
__license__ = "BSD3"

import base64
import datetime
import sys

from argparse import ArgumentParser, RawDescriptionHelpFormatter

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from email.message import EmailMessage
from pathlib import Path


IDENTITY_PREFIX = "identity"
PREF_KEY = "key"
PREF_PUBLIC_NAME = "publicName"
PREF_DESCRIPTION = "description"
PREF_SALT = "salt"
PREF_PICTURE = "picture"
PREF_TEXT = "text"
PREF_PUBLISHED = "published"
PREF_DEFAULT = "default"
PREF_CONFIGURATION = "configuration"

identity_template = {
        PREF_PUBLIC_NAME: '',
        PREF_PUBLISHED: 'false',
        PREF_KEY: '',
        PREF_CONFIGURATION: {
            'includeInGlobalCheck': 'false'
        },
        PREF_DESCRIPTION: '',
        PREF_TEXT: '',
        PREF_PICTURE: '',
        PREF_SALT: ''
    }

SIGNATURE_HEADER = "X-I2PBote-Signature"  # contains the sender's base64-encoded signature
SIGNATURE_VALID_HEADER = "X-I2PBote-Sig-Valid"  # contains the string "true" or "false"
HEADER_WHITELIST = ["From", "Sender", "Reply-To", "In-Reply-To", "To", "CC", "BCC", "Date", "Subject", "Content-Type",
                    "Content-Transfer-Encoding", "MIME-Version", "Message-ID", "X-HashCash", "X-Priority",
                    SIGNATURE_HEADER]
MAX_HEADER_LENGTH = 998


def error(message):
    sys.stderr.write(f'ERROR: {message}')
    sys.exit(1)


def remove_prefix(text, prefix):
    if text.startswith(prefix):
        return text[len(prefix):]
    return text


def load_identities(filepath, template):
    default_ = ''
    current_identities_ = {}
    loaded_identities_ids_ = []
    identities_names_ = []

    identities_file = Path(filepath)
    if identities_file.is_file():
        identities_file.open()
        identities_lines = identities_file.read_text().splitlines()

        for line in identities_lines:
            if len(line) > 0 and '#' == line[0]:
                continue
            if PREF_DEFAULT in line:
                default_ = line.split('=')[1]
            if IDENTITY_PREFIX in line:
                splitted_line = line.split('.')
                identity_id = int(remove_prefix(splitted_line[0], IDENTITY_PREFIX))
                if identity_id not in loaded_identities_ids_:
                    identity_ = template.copy()
                    loaded_identities_ids_.append(identity_id)
                    current_identities_[f'{identity_id}'] = identity_
                if len(splitted_line) == 2:
                    key_value = splitted_line[1].split('=')
                    current_identities_[f'{identity_id}'][key_value[0]] = key_value[1]
                    if key_value[0] == PREF_PUBLIC_NAME:
                        identities_names_.append(key_value[1])
                else:
                    if PREF_CONFIGURATION in splitted_line:
                        key_value = splitted_line[2].split('=')
                        current_identities_[f'{identity_id}']['configuration'][key_value[0]] = key_value[1]
    else:
        error(f'Can\'t open file {identities_file.absolute()}')

    return default_, identities_names_, loaded_identities_ids_, current_identities_


def base_to_key(base_key):
    priv_sign = ''
    if len(base_key) == 172:
        priv_sign = f'A{base_key[129:172]}'
    else:
        error('Unsupported algorithm')

    private_key_byte = base64.b64decode(priv_sign.encode("utf-8"), altchars=b'-~')
    private_int = int.from_bytes(private_key_byte, 'big', signed=False)

    if len(base_key) == 172:
        return ec.derive_private_key(private_int, ec.SECP256R1())
    else:
        error('Unsupported algorithm')


def sign_message(message_bytes, key_):
    sign_ = b''
    if key_.curve.name == 'secp256r1':
        sign_ = key_.sign(message_bytes, ec.ECDSA(hashes.SHA256()))
    return sign_


if __name__ == '__main__':
    parser = ArgumentParser(
        description=__title__,
        formatter_class=RawDescriptionHelpFormatter
    )

    parser.add_argument('-v', '--version', default=None, action='store_true', help='Print version and exit.')
    parser.add_argument('-m', '--messagepath', help='Path to message TXT file')
    parser.add_argument('-i', '--identity', help='Bote identity name')
    parser.add_argument('-f', '--identityfile', help='Bote identities file')
    parser.add_argument('-r', '--recipient', help='Recipient name')
    parser.add_argument('-a', '--recipientidentity', help='Base64 encoded Bote identity')
    parser.add_argument('-s', '--subject', help='Message subject')

    arguments = vars(parser.parse_args())

    if arguments['version']:
        print("{}".format(__title__))
        print("v{}".format(__version__))
        exit(0)

    if not arguments['messagepath']:
        error('--messagepath not specified')

    if not arguments['identity']:
        error('--identity not specified')

    if not arguments['identityfile']:
        error('--identityfile not specified')

    if not arguments['recipient']:
        error('--recipient not specified')

    if not arguments['recipientidentity']:
        error('--recipientidentity not specified')

    if not arguments['subject']:
        error('--subject not specified')

    default, identities_names, identities_ids, identities = load_identities(arguments['identityfile'],
                                                                            identity_template)

    if arguments['identity'] not in identities_names:
        error(f'Identity with name "{arguments["identity"]}" not exist in file {arguments["identityfile"]}')

    current_identity = identity_template.copy()
    for identity in identities:
        if arguments["identity"] == identities[identity][PREF_PUBLIC_NAME]:
            current_identity = identities[identity]

    msg = EmailMessage()

    with open(arguments['messagepath']) as fp:
        msg.set_content(fp.read())

    msg['Date'] = f'{datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S %z %Z")}'
    msg['Subject'] = f'{arguments["subject"]}'

    # For ECDSA256
    if len(current_identity[PREF_KEY]) == 172:
        msg['From'] = f'{current_identity[PREF_PUBLIC_NAME]} <{current_identity[PREF_KEY][:86]}>'
        msg['Sender'] = f'{current_identity[PREF_PUBLIC_NAME]} <{current_identity[PREF_KEY][:86]}>'
    else:
        error('Unsupported algorithm')

    # ToDo: find recipient in AddressBook by name
    msg['To'] = f'{arguments["recipient"]} <{arguments["recipientidentity"]}>'

    key = base_to_key(current_identity[PREF_KEY])
    signature_byte = sign_message(msg.as_bytes(), key)
    signature_base_str = base64.b64encode(signature_byte, altchars=b'-~').decode("utf-8")

    msg[SIGNATURE_HEADER] = signature_base_str

    print(msg.as_string())
