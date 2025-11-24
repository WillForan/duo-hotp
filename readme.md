# Duo HOTP
Duo can authenticate using HOTP - _Hash(message authentication code)-based One-Time Password_.

But some under-documented sorcery is required to find the key to use with the OATH (Initiative for Open Authentication) standard.

[simonseo/nyuad-spammer](https://github.com/simonseo/nyuad-spammer/tree/master/spammer/duo) has code to jump through those hoops.
The interesting parts of `duo.py` are largely copied from there and [`ivanov:pi/fix-code-40002-unsupported-platform`](https://github.com/WillForan/duo-hotp/pull/2).

## Usage
Also see `duo.py -h` or the doc string of [duo.py](duo.py).

1. generate a new duo QR code for an android tablet within your institution's device management portal
2. copy the url of the QR code image   <img src="img/copy_qr_code.png?raw=True" width=100>. It should look like `https://api-e4c9863e.duosecurity.com/frame/qr?value=c53Xoof7cFSOHGxtm69f-YXBpLWU0Yzk4NjNlLmR1b3NlY3VyaXR5LmNvbQ`
3. `./duo.py new 'https://URL-OF-IMAGE'` to register
4. push continue in the browser
5. `./duo.py next` for future authentication with HOTP.

Depending on your organization's configuration, either or both HOTP or TOTP might be enabled.
The OTP base-32 key is the same for both. See [TOTP](#totp) section below and [issue #3 for more](https://github.com/WillForan/duo-hotp/issues/3)
### Convenience
consider adding binding in `sxkd`, `xbindkeys`, etc for
```
duo.py next -s ~/secure/myinstitution_duo.json  | xclip -i
```

Or with `uv`
```
uv run --script /path/to/duo.py next -s ~/secure/duo.json
```

## Warnings
> [!CAUTION]
> `rm duo_response_*.json` once you have a working key/setup.

 * The default `secret.json` file is not encrypted! Be careful where you store it (see `-s` switch).
 * if you generate too many `next` calls w/out passing on to duo, you'll leave the validation window and duo will not authenticate.
 * Initialization logs all output to stdout and to `duo_response_{now}.json`. The information is useful for setup but not needed after.

## Install

```
pip install -r requirements.txt # pyotp docopt requests
./duo.py -h
```

Alternatively, `uv run --script duo.py` will pull depends if needed.

## Tests
testing is limited.
```
python -m doctest duo.py
```

## TODO
 * support GPG to secure secret file

## TOTP
Use of `duo.py` beyond extracting the secret key is specific to Duo's HOTP.
For Time based One Time Passwords (in Duo or others like Google Authenticator, Microsoft Authenticator), look at `oath-toolkit` or [`keepassxc`](https://keepassxc.org/). The base32 key printed at the end of `./duo.py new "$url"` also works as the TOTP key.

```
oathtool --totp --base32 $KEY
# or
pass my-otp-entry | oathtool --base32 --totp -
```

-----

As noted by [@Kodiologist](https://github.com/WillForan/duo-hotp/issues/3#issuecomment-2740374448) [2025-03-20],

For Duo TOTP authentication, the `secrets.json` created herein does not have the correct secret. You'll want `HOTP Secret (B32): …` and use like

```
oathtool --base32 --totp $SECRET
```
