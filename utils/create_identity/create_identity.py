#!/usr/bin/env python3

__title__ = 'Create Bote Identity'
__version__ = "1.0.0"
__author__ = "polistern"
__maintainer__ = "polistern"
__status__ = "Production"
__license__ = "BSD3"

import base64
import datetime
import sys

from argparse import ArgumentParser, RawDescriptionHelpFormatter

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

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
                    current_identity = template.copy()
                    loaded_identities_ids_.append(identity_id)
                    current_identities_[f'{identity_id}'] = current_identity
                if len(splitted_line) == 2:
                    key_value = splitted_line[1].split('=')
                    current_identities_[f'{identity_id}'][key_value[0]] = key_value[1]
                    if key_value[0] == PREF_PUBLIC_NAME:
                        identities_names_.append(key_value[1])
                else:
                    if PREF_CONFIGURATION in splitted_line:
                        key_value = splitted_line[2].split('=')
                        current_identities_[f'{identity_id}']['configuration'][key_value[0]] = key_value[1]

    return default_, identities_names_, loaded_identities_ids_, current_identities_


def fill_new_identity(template, args):
    new_identity = template.copy()

    for name in identities_names:
        if args['name'] == name:
            error(f'Identity with name "{name}" already exist in your file {args["filename"]}. '
                  f'Try to use different name.')
    new_identity['publicName'] = args['name']

    if args['description']:
        new_identity['description'] = args['description']

    if args['picture']:
        with open(args['picture'], "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read())
            new_identity['picture'] = encoded_string.decode("utf-8")

    new_identity['key'] = generate_address(int(arguments['algorithm']))

    return new_identity


def write_to_file(filepath, identities, default_):
    with open(filepath, 'w') as output:
        output.write(datetime.datetime.utcnow().strftime('# %a %b %d %H:%M:%S UTC %Y\n\n'))
        output.write('# If you need to change default identity comment current default '
                     'and uncomment one of the follow\n')

        for identity in identities:
            output.write(f'#{identities[identity]["publicName"]}\n')
            if default_:
                if default_ == identities[identity]["key"][:86]:
                    output.write(f'default={identities[identity]["key"][:86]}\n')
                else:
                    output.write(f'#default={identities[identity]["key"][:86]}\n')
            else:
                default_ = identities[identity]["key"][:86]
                output.write(f'default={identities[identity]["key"][:86]}\n')
        output.write('\n')

        for identity in identities:
            output.write(f'{IDENTITY_PREFIX}{identity}.{PREF_PUBLIC_NAME}='
                         f'{identities[identity][PREF_PUBLIC_NAME]}\n')
            output.write(f'{IDENTITY_PREFIX}{identity}.{PREF_PUBLISHED}='
                         f'{identities[identity][PREF_PUBLISHED]}\n')
            output.write(f'{IDENTITY_PREFIX}{identity}.{PREF_KEY}='
                         f'{identities[identity][PREF_KEY]}\n')
            output.write(f'{IDENTITY_PREFIX}{identity}.{PREF_CONFIGURATION}.includeInGlobalCheck='
                         f'{identities[identity][PREF_CONFIGURATION]["includeInGlobalCheck"]}\n')
            output.write(f'{IDENTITY_PREFIX}{identity}.{PREF_DESCRIPTION}='
                         f'{identities[identity][PREF_DESCRIPTION]}\n')
            output.write(f'{IDENTITY_PREFIX}{identity}.{PREF_TEXT}='
                         f'{identities[identity][PREF_TEXT]}\n')
            output.write(f'{IDENTITY_PREFIX}{identity}.{PREF_PICTURE}='
                         f'{identities[identity][PREF_PICTURE]}\n')
            output.write(f'{IDENTITY_PREFIX}{identity}.{PREF_SALT}='
                         f'{identities[identity][PREF_SALT]}\n\n')


def generate_ecdsa_256():
    # ECDSA256_COMPLETE_BASE64_LENGTH = 172;
    # ECDSA256_COMPLETE_BASE64_PUBLIC_PART_LENGTH = 86;
    key_length_byte = 33

    private_key_1 = ec.generate_private_key(ec.SECP256R1())
    private_key_1_bytes = private_key_1.private_numbers().private_value.to_bytes(key_length_byte, byteorder='big')

    public_key_1 = private_key_1.public_key()
    public_key_1_bytes = public_key_1.public_bytes(encoding=serialization.Encoding.X962,
                                                   format=serialization.PublicFormat.CompressedPoint)

    private_key_1_byte_base_str = base64.b64encode(private_key_1_bytes, altchars=b'-~').decode("utf-8")
    public_key_1_bytes_base_str = base64.b64encode(public_key_1_bytes, altchars=b'-~').decode("utf-8")

    private_key_2 = ec.generate_private_key(ec.SECP256R1())
    private_key_2_bytes = private_key_2.private_numbers().private_value.to_bytes(key_length_byte, byteorder='big')

    public_key_2 = private_key_2.public_key()
    public_key_2_bytes = public_key_2.public_bytes(encoding=serialization.Encoding.X962,
                                                   format=serialization.PublicFormat.CompressedPoint)

    private_key_2_byte_base_str = base64.b64encode(private_key_2_bytes, altchars=b'-~').decode("utf-8")
    public_key_2_bytes_base_str = base64.b64encode(public_key_2_bytes, altchars=b'-~').decode("utf-8")

    public_key = f'{public_key_1_bytes_base_str[1:]}{public_key_2_bytes_base_str[1:]}'
    private_key = f'{private_key_1_byte_base_str[1:]}{private_key_2_byte_base_str[1:]}'

    return f'{public_key}{private_key}'


def generate_address(alg):
    if alg == 2:
        return generate_ecdsa_256()
    else:
        error('Unsupported crypto algorithm')


if __name__ == '__main__':
    parser = ArgumentParser(
        description=__title__,
        formatter_class=RawDescriptionHelpFormatter
    )

    parser.add_argument('-v', '--version', default=None, action='store_true', help='Print version and exit.')
    parser.add_argument('-n', '--name', help='The public name of the identity, included in emails.')
    parser.add_argument('-a', '--algorithm', help='Encryption and signature algorithm. For now only 2', default=2)
    parser.add_argument('-p', '--picture', help='Path to image file')
    parser.add_argument('-d', '--description', help='Description of the identity, only displayed locally.')
    parser.add_argument('-f', '--filename', help='Full path to current identities file.', default='identities.txt')

    arguments = vars(parser.parse_args())

    if arguments['version']:
        print("{}".format(__title__))
        print("v{}".format(__version__))
        exit(0)

    if not arguments['name']:
        error('--name not specified')

    if not arguments['algorithm']:
        error('--algorithm not specified')

    default, identities_names, identities_ids, current_identities = load_identities(arguments['filename'],
                                                                                    identity_template)

    if len(identities_ids) > 0:
        current_identities[f'{max(identities_ids) + 1}'] = fill_new_identity(identity_template, arguments)
    else:
        current_identities[f'{0}'] = fill_new_identity(identity_template, arguments)

    write_to_file(arguments['filename'], current_identities, default)

    exit(0)
