import pyotp
import requests
import base64
import json
import sys, inspect
from os.path import dirname, join, abspath
from urllib import parse

SECRETFILE = 'secrets.json'
SECRETFILE = join(dirname(abspath(inspect.stack()[0][1])), SECRETFILE)


def qr_url_to_activation_url(qr_url):
	#--- Create request URL
	data = parse.unquote(qr_url.split('?value=')[1])           # get ?value=XXX
	code = data.split('-')[0].replace('duo://', '')            # first half of value is the activation code
	hostb64 = data.split('-')[1]                               # second half of value is the hostname in base64
	host = base64.b64decode(hostb64 + '='*(-len(hostb64) % 4)) # Same as "api-e4c9863e.duosecurity.com"
	activation_url = 'https://{host}/push/v2/activation/{code}'.format(host=host.decode("utf-8"), code=code) # this api is not publicly known
	print(activation_url)
	return activation_url

def activate_device(activation_url):
	'''Activates through activation url and returns HOTP key '''
	#--- Get response which will be a JSON of secret keys, customer names, etc.
	#--- Expected Response: {'response': {'hotp_secret': 'blahblah123', ...}, 'stat': 'OK'}
	#--- Expected Error: {'code': 40403, 'message': 'Unknown activation code', 'stat': 'FAIL'}
	response = requests.post(activation_url)
	response_dict = json.loads(response.text)
	if response_dict['stat'] == 'FAIL':
		raise Exception("The given URL is invalid. Try a new QR/Activation URL")
	print(response_dict)

	hotp_secret = response_dict['response']['hotp_secret']
	return hotp_secret

def save_secret(hotp_secret, count):
	'''Save to secrets.json
	hotp_secret should look like "7e1c0372fec015ac976765ef4bb5c3f3" 
	count should be an int'''
	secrets = {
		"hotp_secret" : hotp_secret,
		"count" : count
	}
	with open(SECRETFILE, "w") as f:
		json.dump(secrets, f)

def load_secret():
	try:
		with open(SECRETFILE, "r") as f:
			secret_dict = json.load(f)
	except Exception as e:
		raise
	return secret_dict


def HOTP():
	'''Usage: generate = HOTP(); passcode = generate()'''
	#--- Create HOTP object
	secret_dict = load_secret()
	HOTP.count = secret_dict.get("count", 0)
	hotp_secret = secret_dict.get("hotp_secret")
	encoded_secret = base64.b32encode(hotp_secret.encode("utf-8"))
	hotp = pyotp.HOTP(encoded_secret)   # As long as the secret key is the same, the HOTP object is the same

	#--- Generate new passcode
	def generate():
		passcode = hotp.at(HOTP.count)
		HOTP.count += 1
		save_secret(hotp_secret, HOTP.count)
		return passcode
	return generate

def main(qr_url):
	activation_url = qr_url_to_activation_url(qr_url)
	hotp_secret = activate_device(activation_url)
	save_secret(hotp_secret, count=0)

	# Generate 10 OTPs!
	# You may use any OTP but all previous OTPs will become invalid
	print("HOTP Secret:", base64.b32encode(hotp_secret.encode("utf-8")))

	print("First 10 One Time Passwords:")
	generateOTP = HOTP()
	for i in range(10):
		print(generateOTP())

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print("Usage: python3 duo.py <url-to-duo-qr>")
		exit()
	qr_url = sys.argv[1]
	main(qr_url)
