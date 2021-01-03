# Duo HOTP
Duo can authenticate using HOTP - _Hash(message authentication code)-based One-Time Password_.

But it has some proprietary covers over the OATH (Initiative for Open Authentication) standard.

[simonseo/nyuad-spammer](https://github.com/simonseo/nyuad-spammer/tree/master/spammer/duo) has code to work around this. 
`duo.py` is largely copied from there

## Usage
also see `duo.py -h` or the doc string of [duo.py](duo.py)

1. generate a new duo QR code for an android tablet within your institution's device management portal
2. copy the url of the QR code image   <img src="img/copy_qr_code.png?raw=True" width=100>. it should look like `https://api-e4c9863e.duosecurity.com/frame/qr?value=c53Xoof7cFSOHGxtm69f-YXBpLWU0Yzk4NjNlLmR1b3NlY3VyaXR5LmNvbQ`
3. `./duo.py new 'https://URL-OF-IMAGE'` to register
4. push continue in the browser
5. `./duo.py next` for future authentication

### convenience
consider adding binding in `sxkd`, `xbindkeys`, etc for
```
duo.py next -s ~/secure/myinstitution_duo.json  | xclip -i
```

## Warnings
 * The default `secret.json` file is not encrypted! Be careful where you store it (see `-s` switch).
 * if you generate too many `next` calls w/out passing on to duo, you'll leave the validation window and duo will not authenticate.

## Tests
testing is limited.
```
python -m doctest duo.py
```

## TODO
 * support GPG to secure secret file

## TOTP
`duo.py` is specific to duo's HOTP.
For time based one time passwords (Google Authenticator, Microsoft Authenticator), look at `oath-toolkit`

```
KEY=$(zbarimg /path/to/qr-image.png)
oathtool --totp --base32 $KEY
```
