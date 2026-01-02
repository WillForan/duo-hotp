#!/usr/bin/env python3
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "docopt",
#     "pycryptodome",
#     "pyotp",
#     "requests"
# ]
# ///
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
import datetime
import inspect
import json
import os
import re
from os.path import abspath, dirname, isfile, join
from urllib import parse

import pyotp
import requests
from Crypto.PublicKey import RSA
from docopt import docopt


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


def activation_url_duo(qr_url):
    """
    Create request URL from duo:// QR code imae url.
    Deprecated 2026-01 (?)
    @param qr_url contains '?value=duo://{code}-{host}' as url within QR code
    @returns undocumented v2/activation link

    >>> eg_url = 'https://blah.duosecurity.com/frame/qr?value=duo%3A%2F%2Fc53Xoof7cFSOHGxtm69f-YXBpLWU0Yzk4NjNlLmR1b3NlY3VyaXR5LmNvbQ'
    >>> activation_url_duo(eg_url)
    'https://api-e4c9863e.duosecurity.com/push/v2/activation/c53Xoof7cFSOHGxtm69f?customer_protocol=1'
    """
    # get ?value=XXX
    data = parse.unquote(qr_url.split("?value=")[1])
    # first half of value is the activation code
    code = data.split("-")[0].replace("duo://", "")
    # second half of value is the hostname in base64
    hostb64 = data.split("-")[1]
    # Same as "api-e4c9863e.duosecurity.com"
    host = base64.b64decode(hostb64 + "=" * (-len(hostb64) % 4))
    host = host.decode("utf-8")
    # this api is not publicly known
    activation_url = f"https://{host}/push/v2/activation/{code}?customer_protocol=1"
    return activation_url


def activation_url_https(qr_url):
    """Create request URL from QR image url with https:// (vs duo://)
    First seen 2026-01 (github.com/SleepyLeslie; PR #5)
    @param qr_url like ?value=https://m-{host}/activate/{code}
    @returns undocumented v2/activation link

    >>> eg_url = 'https://blah.duosecurity.com/frame/qr?value=https%3A%2F%2Fm-xxxxxxxx.duosecurity.com%2Factivate%2Fyyyyyyyyyyyyyyyyyyyy'
    >>> activation_url_https(eg_url)
    'https://api-xxxxxxxx.duosecurity.com/push/v2/activation/yyyyyyyyyyyyyyyyyyyy?customer_protocol=1'
    """
    # get ?value=XXX
    data = parse.unquote(qr_url.split("?value=")[1])
    rematch = re.search(r"https?://m-(?P<host>[^/]+)/activate/(?P<code>[^/]+)", data)
    if rematch is None:
        raise RuntimeError("Invalid activation URL: cannot extract host and code")
    # this api is not publicly known
    activation_url = f"https://api-{rematch.group('host')}/push/v2/activation/{rematch.group('code')}?customer_protocol=1"
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


def activate_device(activation_url, write_result=True):
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
    if write_result:
        now = datetime.datetime.now().strftime("%s")
        fname = f"duo_response_{now}.json"
        print(
            f"# !! WARNING: backing up to '{fname}' for external use. Remove once setup !!"
        )
        with open(fname, "w") as f:
            f.write(response.text)

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
            print(f"""MANUALLY EDIT: {{"hotp_secret": "{hotp_secret}", "count": 0}}""")
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
            raise Exception("Bad secret input")

        encoded_secret = b32_encode(self.hotp_secret)
        self.pyhotp = pyotp.HOTP(encoded_secret)
        return self.pyhotp

    def generate(self):
        "generate and update counter in secret_file"
        if self.pyhotp is None or self.count is None:
            raise Exception("cannot generate without first loading a secret")
        passcode = self.pyhotp.at(self.count)
        self.count += 1
        self.save_secret()
        return passcode


def mknew(qr_url, secret_file):
    """load QR code, send activation request, generate first code."""

    # given link inside QR code (like if read with zbarimg)
    if re.search(r"/activate/[A-Za-z0-9]+$", qr_url):
        res = requests.get(qr_url, timeout=100)
        m = re.search(r'duo&#x3a;&#x2f;&#x2f;([^"]+)', res.text)
        if not m:
            raise Exception(
                f"Could not find duo link in '{qr_url}'. "
                + "Expect '/activate/' url to match 'duo&#x3a;&#x2f;&#x2f;'. "
                + "**Consider providing the url to the QR code instead.**"
            )

        # kludge: reuse code by faking the original link format
        # TODO: does QR containing link still match expected duo://?
        activation_url = activation_url_duo(f"discard?value={m.group(1)}")

    # if given url to actual QR image
    elif re.search(r"value=http", qr_url):
        activation_url = activation_url_https(qr_url)
    elif re.search(r"value=duo", qr_url):
        activation_url = activation_url_duo(qr_url)
    else:
        raise Exception(
            f"Don't know how to handle url like '{qr_url}'."
            + "Expecting URL of QR code. Should contain 'value=https' or 'value=duo'."
        )

    print(activation_url)
    hotp_secret = activate_device(activation_url)
    print("OTP Secret (B32):", b32_encode(hotp_secret))

    hotp = HOTP(secret_file, hotp_secret)

    print("first key")
    print(hotp.generate())


def cli_hotp():
    args = docopt(__doc__, version="Duo HOTP 2021.01")

    if args["new"]:
        secret_file = find_secret(args["-s"], must_exist=False)
        mknew(args["<qr_url>"], secret_file)

    elif args["next"]:
        secret_file = find_secret(args["-s"])
        hotp = HOTP(secret_file)
        print(hotp.generate())


if __name__ == "__main__":
    cli_hotp()
