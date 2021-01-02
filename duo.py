#!/usr/bin/env python3
"""Duo HOTP

Usage:
    duo_hotp [-s <secret.json>] new <qr_url>
    duo_hotp [-s <secret.json>] next
    duo_hotp -h | --help

Options:
    -h --help     Show this screen.
    -s PATH       provide PATH of secret.json file
"""
import base64
import inspect
import json
import os
import pyotp
import requests
from docopt import docopt
from os.path import dirname, join, abspath, isfile
from urllib import parse


def b32_encode(key):
    return base64.b32encode(key.encode("utf-8"))


def find_secret(path=None, must_exist=False):
    """use input, env, or script directory"""
    if path is None and os.environ.get("DUO_SECRETFILE", None) is not None:
        path = os.environ("DUO_SECRETFILE")

    if path is None:
        bin_dir = dirname(abspath(inspect.stack()[0][1]))
        path = join(bin_dir, "secrets.json")

    if not isfile(path) and must_exist:
        print(f"'{path}' does not exist!")
        raise Exception(f"Cannot find secret json file")

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
    activation_url = "https://{host}/push/v2/activation/{code}".format(
        host=host.decode("utf-8"), code=code
    )
    print(activation_url)
    return activation_url


def activate_device(activation_url):
    """Activates through activation url and returns HOTP key """
    # --- Get response which will be a JSON of secret keys, customer names, etc
    # --- Expected Response:
    #     {'response': {'hotp_secret': 'blahblah123', ...}, 'stat': 'OK'}
    # --- Expected Error:
    #     {'code': 40403, 'message': 'Unknown activation code', 'stat': 'FAIL'}
    response = requests.post(activation_url)
    response_dict = json.loads(response.text)
    if response_dict["stat"] == "FAIL":
        raise Exception("Activation failed! Try a new QR/Activation URL")
    print(response_dict)

    hotp_secret = response_dict["response"]["hotp_secret"]
    return hotp_secret


class HOTP:
    def __init__(self, path, hotp_secret=None):
        """load for secrete file
        or if given a secret, make the file
        """
        self.secret_file = path  # where to save
        self.count = None  # number of hits on this secret
        self.hotp_secret = None  # like "7e1c0372fec015ac976765ef4bb5c3f3"
        self.hotp = None  # pyotp

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
            raise Exception("not overwritting existing file")
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
        """sets self.hotp to a pyopt.HOTP object using secret.json"""
        with open(self.secret_file, "r") as f:
            secret_dict = json.load(f)

        self.count = secret_dict.get("count", -1)
        self.hotp_secret = secret_dict.get("hotp_secret", None)
        if self.count < 0 or self.hotp_secret is None:
            print("Missing values in '{self.secret_file}")
            raise Exception("Bad input")

        encoded_secret = b32_encode(self.hotp_secret)
        self.hotp = pyotp.HOTP(encoded_secret)
        return self.hotp

    def generate(self):
        passcode = self.hotp.at(self.count)
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
    args = docopt(__doc__, version="Duo HOTP 1.0")

    if args["new"]:
        secret_file = find_secret(args["-s"], must_exist=False)
        mknew(args["<qr_url>"], secret_file)

    elif args["next"]:
        print(args)
        secret_file = find_secret(args["-s"])
        hotp = HOTP(secret_file)
        print(hotp.generate())
