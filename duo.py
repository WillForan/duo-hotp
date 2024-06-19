#!/usr/bin/env python3
"""Duo HOTP

Usage:
    duo_hotp new <qr_url> [-s <secret.json>]
    duo_hotp next [-s <secret.json>]
    duo_hotp -h | --help

Options:
    -h --help     Show this screen.
    -s PATH       provide PATH of secret.json file

Large parts of code copied from
 https://github.com/simonseo/nyuad-spammer/tree/master/spammer/duo
"""
import base64
import inspect
import json
import os
import pyotp
import requests
from Crypto.PublicKey import RSA
from docopt import docopt
from os.path import dirname, join, abspath, isfile
from urllib import parse


def b32_encode(key):
    return base64.b32encode(key.encode("utf-8"))


def find_secret(path=None, must_exist=True):
    """use input, env, or script directory
    >>> os.path.basename(find_secret(must_exist=False)) # default
    'secrets.json'
    >>> os.environ["DUO_SECRETFILE"] = "a/b"
    >>> find_secret(must_exist=False)                   # env
    'a/b'
    >>> find_secret("foobar", False)                    # explicit
    'foobar'
    """
    if path is None and os.environ.get("DUO_SECRETFILE", None) is not None:
        path = os.environ["DUO_SECRETFILE"]

    if path is None:
        bin_dir = dirname(abspath(inspect.stack()[0][1]))
        path = join(bin_dir, "secrets.json")

    if not isfile(path) and must_exist:
        print(f"'{path}' does not exist!")
        raise Exception("Cannot find secret json file")

    return path


def qr_url_to_activation_url(qr_url):
    "Create request URL"
    # get ?value=XXX
    data = parse.unquote(qr_url.split("?value=")[1])
    # first half of value is the activation code
    code = data.split("-")[0].replace("duo://", "")
    # second half of value is the hostname in base64
    hostb64 = data.split("-")[1]
    # Same as "api-e4c9863e.duosecurity.com"
    host = base64.b64decode(hostb64 + "=" * (-len(hostb64) % 4))
    # this api is not publicly known
    activation_url = "https://{host}/push/v2/activation/{code}?customer_protocol=1".format(
        host=host.decode("utf-8"), code=code
    )
    print(activation_url)
    return activation_url


def activate_params():
    """
    Generate paramaters for activiating a device.

    >>> p = activate_params()
    >>> len(p['pubkey'])
    450
    """
    # publickey not public_key in python3-pycryptodomex-3.20.0 (Fedora 40)
    # fix from @gsomlo, see
    #   https://github.com/WillForan/duo-hotp/issues/3#issuecomment-2176260202
    # 'pip install pycryptodome==3.20.0' has both publickey and public_key
    try:
        pubkey = RSA.generate(2048).public_key().export_key("PEM").decode()
    except AttributeError:
        pubkey = RSA.generate(2048).publickey().exportKey("PEM").decode()

    params = {
        "pkpush": "rsa-sha512",
        "pubkey": pubkey,
        "jail broken": "false",
        "Architecture": "arm64",
        "Legion": "US",
        "App_id": "com.duosecurity.duomobile",
        "full_disk_encryption": "true",
        "passcode_status": "true",
        "platform": "Android",
        "app_version": "3.49.0",
        "app_build_number": "323001",
        "version": "11",
        "manufacturer": "unknown",
        "language": "en",
        "model": "Pixel 3a",
        "security_patch_level": "2021-02-01",
    }
    return params


def activate_device(activation_url):
    """Activates through activation url and returns HOTP key"""
    # --- Get response which will be a JSON of secret keys, customer names, etc
    # --- Expected Response:
    #     {'response': {'hotp_secret': 'blahblah123', ...}, 'stat': 'OK'}
    # --- Expected Error:
    #     {'code': 40403, 'message': 'Unknown activation code', 'stat': 'FAIL'}

    params = activate_params()
    response = requests.post(activation_url, params=params, timeout=300)
    response_dict = json.loads(response.text)
    if response_dict["stat"] == "FAIL":
        raise Exception("Activation failed! Try a new QR/Activation URL")
    print(response_dict)

    hotp_secret = response_dict["response"]["hotp_secret"]
    return hotp_secret


class HOTP:
    """read and write from json file to generate HMAC-based one time password
    using pyotp

    >>> if isfile('example.json'): os.unlink('example.json') # cleanup

    HOTP can create and immedately use a secret
    >>> hotp = HOTP('example.json', "7e1c0372fec015ac976765ef4bb5c3f3")
    >>> isfile('example.json')
    True
    >>> hotp.count
    0
    >>> passcode = hotp.generate()
    >>> hotp.count
    1

    But wont over write an existing file
    >>> fail = HOTP('example.json', "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
    Traceback (most recent call last):
     ...
    Exception: Not overwritting existing file

    Instead, reload the last settings
    >>> hotp_again = HOTP('example.json')
    >>> hotp_again.count
    1
    """

    def __init__(self, path, hotp_secret=None):
        """load for secret file
        or if given a secret, make the file
        """
        self.secret_file = path  # where to save
        self.count = None  # number of hits on this secret
        self.hotp_secret = None  # like "7e1c0372fec015ac976765ef4bb5c3f3"
        self.pyhotp = None  # pyotp

        # if we are initializing with a secret
        # we should create a new file
        if hotp_secret is not None:
            self.init_secret(hotp_secret)

        self.load_secret()

    def init_secret(self, hotp_secret):
        """create file with 0 counter"""
        if isfile(self.secret_file):
            print(f"'{self.secret_file}' already exits. not overwriting!")
            print(f"MANUALLY EDIT: counter to 0 and htop to {hotp_secret}")
            raise Exception("Not overwritting existing file")
        self.hotp_secret = hotp_secret
        self.count = 0
        self.save_secret()

    def save_secret(self):
        """Save to secrets.json
        hotp_secret should look like "7e1c0372fec015ac976765ef4bb5c3f3"
        count should be an int"""
        secrets = {"hotp_secret": self.hotp_secret, "count": self.count}
        with open(self.secret_file, "w") as f:
            json.dump(secrets, f)

    def load_secret(self):
        """sets self.pyhotp to a pyotp.HOTP object using secret.json"""
        with open(self.secret_file, "r") as f:
            secret_dict = json.load(f)

        self.count = secret_dict.get("count", -1)
        self.hotp_secret = secret_dict.get("hotp_secret", None)
        if self.count < 0 or self.hotp_secret is None:
            print("Missing values in '{self.secret_file}")
            raise Exception("Bad input")

        encoded_secret = b32_encode(self.hotp_secret)
        self.pyhotp = pyotp.HOTP(encoded_secret)
        return self.pyhotp

    def generate(self):
        "generate and update counter in secret_file"
        passcode = self.pyhotp.at(self.count)
        self.count += 1
        self.save_secret()
        return passcode


def mknew(qr_url, secret_file):
    """load QR code, send activation request, generate first code"""

    activation_url = qr_url_to_activation_url(qr_url)
    hotp_secret = activate_device(activation_url)
    print("HOTP Secret (B32):", b32_encode(hotp_secret))

    hotp = HOTP(secret_file, hotp_secret)

    print("first key")
    print(hotp.generate())


if __name__ == "__main__":
    args = docopt(__doc__, version="Duo HOTP 2021.01")

    if args["new"]:
        secret_file = find_secret(args["-s"], must_exist=False)
        mknew(args["<qr_url>"], secret_file)

    elif args["next"]:
        secret_file = find_secret(args["-s"])
        hotp = HOTP(secret_file)
        print(hotp.generate())
