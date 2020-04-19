import websocket
import sys, os, time, json
import base64, donna25519
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import pyqrcode, png

def help():
	print('''Run Without Parameters to KeyGen
	Then, run like this: whoopsapp.py [serverToken] [clientToken]''')

def on_message(ws, message):
	if type(message) == str:
		if message[0:5] == "whoop":
			with open('config.json', 'r') as file:
				config = json.load(file)
			result = message[6:]
			result = json.loads(result)
			
			# ----QR Code Generation with Curve25519----

			# Generate Private and Public Keys
			privKey = donna25519.PrivateKey(os.urandom(32))
			pubKey = privKey.get_public()
			
			# Serialize Private and Public keys
			curveKeys = {'curveKeys':{'privKey':base64.b64encode(privKey.private).decode('utf-8'),'pubKey':base64.b64encode(pubKey.public).decode('utf-8')}}
			config.update(curveKeys)
			with open('config.json', 'w') as file:
				json.dump(config, file)
			
			# Concatenate QR String and Generate QR
			qrString = result['ref'] + ',' + base64.b64encode(pubKey.public).decode('utf-8') + ',' + config['clientId']
			qr = pyqrcode.create(qrString)
			qr.png('tempqr.png', scale=5)
			
			print('Waiting for QR Scan')
		elif 'secret' in message:
			# Read Config
			with open('config.json','r') as file:
				config = json.load(file)
			
			# Get Json of Response
			message = message.split(',', 2)
			info = message[2][:-1]
			info = json.loads(info)
			
			#----Key Gen----
			
			secret = base64.b64decode(info['secret'])
			
			# Generate Shared Secret
			privKey = donna25519.PrivateKey.load(base64.b64decode(config['curveKeys']['privKey'].encode('utf-8')))
			sharedSecret = privKey.do_exchange(donna25519.PublicKey(secret[:32]))

			# HKDF to expand key to 80 bytes using HMAC-SHA256 and salt as zeroes
			sharedSecretExpanded = HKDF(sharedSecret, 80, None, SHA256, 1)
			keysEncrypted = sharedSecretExpanded[64:] + secret[64:]
			
			# HMAC Validation (Hash Message Authentication Code)
			h = HMAC.new(sharedSecretExpanded[32:64], digestmod=SHA256)
			h.update(secret[:32] + secret[64:])
			digest = h.digest()
			if (digest == secret[32:64]):
				print('HMAC Validated')
			else:
				print('HMAC Invalid')

			# Decrypt Using AES-CBC-256 where IV is first 16 bytes of ciphertext
			cipher = AES.new(sharedSecretExpanded[:32], AES.MODE_CBC, keysEncrypted[:AES.block_size])
			keysDecrypted = unpad(cipher.decrypt(keysEncrypted[AES.block_size:]), AES.block_size)
			
			messageKeys = {'messageKey':{'encKey':base64.b64encode(keysDecrypted[:32]).decode('utf-8'),'macKey':base64.b64encode(keysDecrypted[32:64]).decode('utf-8')}}
			
			# Serialize
			config.update(info)
			config.update(messageKeys)
			with open('config.json', 'w') as file:
				json.dump(config, file)
		else:
			print(message)
	else:
		#----Decrypting Messages from Server----
		with open('config.json', 'r') as file:
			config = json.load(file)
		
		message = str(message).split(',', 1)
		message = message[1].encode()
		
		print('Message is: ' + str(len(message)) + ' bytes size.')
		
		# HMAC Validation
		h = HMAC.new(base64.b64decode(config['messageKey']['macKey'].encode('utf-8')), digestmod=SHA256)
		h.update(message[32:])
		digest = h.digest()
		if (digest == message[:32]):
			print('HMAC Validated')
		else:
			print('HMAC Invalid')
			print(digest)
			print(message[:32])
		
		# Decrypt Using AES-CBC-256
		cipher = AES.new(base64.b64decode(config['messageKey']['encKey'].encode('utf-8')), AES.MODE_CBC, message[32:][:AES.block_size])
		decryptedContent = unpad(cipher.decrypt(message[32:][AES.block_size:]), AES.block_size)
		print(decryptedContent)

def on_error(ws, error):
	print('Error:')
	print(error)
	
def on_close(ws):
	print('Connection Closed')

# Logging In, QR Generation 
def on_open(ws):
	with open('config.json', 'r') as file:
		config = json.load(file)
	if config['isGen'] == 0:
		print('Connected')
	elif config['isGen'] == 1:
	
		# ----Logging In----
		
		print('Logging In')
		# Arbitrary Tag
		messageTag = 'whoop'
		
		# Log In Message e.g. 
		# messageTag,["admin","init",[0,3,2390],["Long browser description","ShortBrowserDesc"],"clientId",true]
		ws.send(messageTag + ',["admin","init",[2,2013,7],["WhatsApp Auto Bot","WhatsApp Python Bot"],"' + config['clientId'] + '",true]')

# Vars
url = 'wss://web.whatsapp.com/ws'
headers = {
	'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:75.0) Gecko/20100101 Firefox/75.0',
	'Origin': 'https://web.whatsapp.com'
}

# Generate 16 base64 encoded bytes as client id, whether the need to generate and save to config file
clientId = base64.b64encode(os.urandom(16)).decode('utf-8')
isGen = 1

# Key Gen if no params
if len(sys.argv) == 3:
	isGen = 0
config = {'isGen':isGen, 'clientId':clientId}
with open('config.json', 'w') as file:
	json.dump(config,file)
'''
if __name__ == '__main__':
	ws = websocket.create_connection(url,header=headers)
	print('Connected')
	# ----Logging In----
	
	# Generate 16 base64 encoded bytes as client id
	clientId = base64.b64encode(os.urandom(16)).decode('utf-8')
	# Arbitrary Tag
	messageTag = 'whoop'
	# Log In Message e.g. 
	# messageTag,["admin","init",[0,3,2390],["Long browser description","ShortBrowserDesc"],"clientId",true]
	ws.send(messageTag + ',["admin","init",[2,2013,7],["WhatsApp Auto Bot","WhatsApp Python Bot"],"' + clientId + '",true]')
	result = ws.recv()[len(messageTag)+1:]
	result = json.loads(result)
	
	# ----QR Code Generation with Curve25519----
	
	# Generate Private and Public Keys
	privKey = donna25519.PrivateKey(os.urandom(32))
	pubKey = privKey.get_public()
	
	# Concatenate QR String and Generate QR
	qrString = result['ref'] + ',' + base64.b64encode(pubKey.public).decode('utf-8') + ',' + clientId
	qr = pyqrcode.create(qrString)
	qr.png('tempqr.png', scale=5)
	
	print('Waiting for QR Scan')
	while False:
		try:
			result = ws.recv()
		except:
			print('Waiting for QR Scan')
			time.sleep(5)
	print(result)
	#os.remove('tempqr.png')
	ws.close()
'''

websocket.enableTrace(True)
ws = websocket.WebSocketApp(url, on_message=on_message, on_error=on_error, on_close=on_close, header=headers)
ws.on_open = on_open
ws.run_forever()
# print(str(sys.argv))