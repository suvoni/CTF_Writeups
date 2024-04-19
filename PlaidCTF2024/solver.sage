import time
import zlib
import hashlib
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Util.number import long_to_bytes
from pwn import *
import binascii


# SETTINGS
own_ip_address = '127.0.0.1' # own public IP, hosting the DNS-server on port 53/UDP as well as a webserver on port 80/TCP.
# challenge server settings
server = 'dhcppp.chal.pwni.ng' # remote service
port = 1337


# Contstants
dhcp_server_mac = bytes.fromhex("1b 7d 6f 49 37 c9")
flag_server_mac = bytes.fromhex("53 79 82 b5 97 eb")
ip_dot_3 = '192.168.1.3'
gateway_ip = '192.168.1.1'

# functions from the original server file
def calc_crc(msg):
	return zlib.crc32(msg).to_bytes(4, "little")
def sha256(msg):
	return hashlib.sha256(msg).digest()
def byte_xor(d1, d2):
	'''Performs a byte-wise XOR on both data-streams.'''
	return bytes([(a^^b) for a,b in zip(d1, d2)])

dhcp_req_pkt = bytearray(
	flag_server_mac +
	dhcp_server_mac +
	# msg:
	b'\x01' + # DHCP request
	b''     + # rest of msg
	b'\x00'
)

crc32s = {} # hex(crc32) -> leased ip
def precompute_crc32(dhcp_req_pkt):
	global crc32s
	# precompute answer-crc32s:
	for i in range(2, 64): # needs 2, because if you kick rngserver_0 out of the leases, then IP 192.168.1.2 is used!
		ip = f'192.168.1.{i}'
		crc_pkt = bytearray(
			bytes([int(x) for x in ip.split('.')]) +
			bytes([int(x) for x in '192.168.1.1'.split('.')]) +
			bytes([255, 255, 255, 0]) +
			bytes([8, 8, 8, 8]) +
			bytes([8, 8, 4, 4]) +
			dhcp_req_pkt[12+1:] +
			b"\x00"
		)
		crc32s[binascii.hexlify(calc_crc(crc_pkt)).decode()] = ip

def request_ip_from_dhcp(flag_print = False, dhcp_req_pkt = dhcp_req_pkt):
	'''Requests an IP from the DHCP and returns it.'''
	global crc32s
	# prompt
	prompt = conn.readuntil(b'> ').decode()
	#print(prompt, end='')
	# send ip lease request to DHCP Server
	hex_req = binascii.hexlify(dhcp_req_pkt)
	#print('dhcp packet request:', hex_req.decode())
	conn.sendline(hex_req)
	# read response:
	resp = conn.readline().decode().strip()
	#print('resp', resp)
	resp_distant_mac = resp[:12] # dhcp mac
	#print('resp_distant_mac', resp_distant_mac)
	resp_my_mac = resp[12:24] # your own mac
	#print('resp_my_mac', resp_my_mac)
	resp_lease_msg = resp[24:-8]
	resp_lease_msg_2byte = resp_lease_msg[:2] # 02
	resp_lease_msg_ct = resp_lease_msg[2:-56]
	resp_lease_msg_tag = resp_lease_msg[-56:-24] # 16 bytes tag
	resp_lease_msg_modified_nonce = resp_lease_msg[-24:] # 12 bytes nonce
	resp_crc32 = resp[-8:]
	# Precompute crc32s on the first usage; or when the dhcp_req_pkt changes in content => resp_crc32 not in crc32s.keys()
	if resp_crc32 not in crc32s.keys():
		precompute_crc32(dhcp_req_pkt)
	if flag_print:
		print('resp_lease_msg', resp_lease_msg)
		print('resp_lease_msg_2byte', resp_lease_msg_2byte)
		print('resp_lease_msg_ct', resp_lease_msg_ct)
		print('resp_lease_msg_tag', resp_lease_msg_tag)
		print('resp_lease_msg_modified_nonce', resp_lease_msg_modified_nonce)
		print('resp_crc32', resp_crc32, ', associated IP:', crc32s[resp_crc32])
		print('Got IP:', crc32s[resp_crc32])
	return bytes.fromhex(resp_lease_msg_ct), bytes.fromhex(resp_lease_msg_tag), bytes.fromhex(resp_lease_msg_modified_nonce), crc32s[resp_crc32] #.split('.')[-1]

def send_message_to_flag_server(packet):
	'''Send the packet to the FlagServer'''
	# prompt
	prompt = conn.readuntil(b'> ').decode()
	#print(prompt, end='')
	# send message to FlagServer
	hex_req = binascii.hexlify(packet)
	print('Message to FlagServer:', hex_req.decode())
	conn.sendline(hex_req)
	# read response:
	resp = conn.readline().decode().strip()
	print(resp)

def encrypt_custom_message_with_dhcp(custom_message_data):
	'''Returns a keystream for a DHCP-offer message'''
	global flag_server_mac, dhcp_server_mac
	dhcp_req_pkt = bytearray(
		flag_server_mac + # src mac
		dhcp_server_mac + # dst mac
		# msg:
		b'\x01' + # DHCP request
		custom_message_data + # rest of msg
		b'\x00'
	)
	ct, tag, nonce, ip = request_ip_from_dhcp(True, dhcp_req_pkt) # IP: *.*.*.3
	packet = bytearray(
		bytes([int(x) for x in ip.split(".")]) +
		bytes([int(x) for x in "192.168.1.1".split(".")]) +
		bytes([255, 255, 255, 0]) + # subnet mask
		bytes([8, 8, 8, 8]) + # dns server 1
		bytes([8, 8, 4, 4]) + # dns server 2
		dhcp_req_pkt[12+1:] +
		b"\x00"
	)
	assert(len(packet) == 48)
	assert(len(ct) == 48)
	key_stream = byte_xor(ct, packet)
	return key_stream, packet, ct, tag, nonce, ip



conn = remote(server, port)
print(conn.readline().decode())
print('== FINISHED SERVER BOOT ==')


######################################################
###  Get two ciphertexts using the same key/nonce  ###
######################################################


# request enough IPs to remove the 'rngserver_0' from the list of leased IPs...:
print('Cycling through some IPs ...')
for _ in range(61):
	_, _, _, ip = request_ip_from_dhcp(False)
print('No more "rngserver" in the list of leased IPs')
print('Now the lavalamp always returns "sha256(RNG_INIT)!"')
# next IP: *.*.*.3

# lease an IP for the flag_server and get a keystream of specified length for the specified IP
print('Reading key_stream for IP 192.168.1.3 with custom message #1')
_, pkt1, ct1, tag1, nonce1, _ = encrypt_custom_message_with_dhcp((b'\x00'*12) + (b'\x01'*14)) # uses IP: *.*.*.3

print('Cycling through some IPs ...')
for _ in range(61):
	_, _, _, ip = request_ip_from_dhcp(False)
# next IP: *.*.*.3

print('Reading key_stream for IP 192.168.1.3 with custom message #2')
_, pkt2, ct2, tag2, nonce2, _ = encrypt_custom_message_with_dhcp((b'\x00'*12) + (b'\x02'*14)) # uses IP: *.*.*.3


#########################################
###  Poly1305 key/nonce reuse attack  ###
#########################################


# https://datatracker.ietf.org/doc/html/rfc7539#section-2.8 
msg1 = ct1 + b'\x00'*8 + long_to_bytes(len(ct1)) + b'\x00'*7
msg2 = ct2 + b'\x00'*8 + long_to_bytes(len(ct2)) + b'\x00'*7
assert(len(msg1) % 16 == 0)
assert(len(msg2) % 16 == 0)
assert(len(msg1) == len(msg2))
assert(len(msg1) == 64)

# https://en.wikipedia.org/wiki/Poly1305
p = 2**130 - 5
L = len(msg1)
q = L // 16
assert(q == 4)

m1_chunks = [msg1[i*16:i*16+16] + b'\x01' for i in range(q)]
m2_chunks = [msg2[i*16:i*16+16] + b'\x01' for i in range(q)]

coeffs_1 = []
coeffs_2 = []
for i in range(q):
	k = 0
	c_i_1 = 0
	c_i_2 = 0
	for j in range(0, 128+1, 8):
		c_i_1 += m1_chunks[i][k] * 2**j
		c_i_2 += m2_chunks[i][k] * 2**j
		k += 1
	coeffs_1.append(c_i_1)
	coeffs_2.append(c_i_2)

a1 = int.from_bytes(tag1, 'little')
a2 = int.from_bytes(tag2, 'little')

# https://en.wikipedia.org/wiki/Poly1305#Security
# https://crypto.stackexchange.com/questions/83629/forgery-attack-on-poly1305-when-the-key-and-nonce-reused
R.<r> = GF(p)[]
poly1305_1 = sum([coeffs_1[i] * r**(q-i) for i in range(q)]) 
poly1305_2 = sum([coeffs_2[i] * r**(q-i) for i in range(q)])

valid_roots = []
for k in (-4, -3, -2, -1, 0, 1, 2, 3, 4):
	f = poly1305_1 - poly1305_2 - (a1 - a2 + k*2**128)
	roots = f.roots()
	for root in roots:
		if root[0] <= 2**128:
			valid_roots.append(root[0])
print('valid_roots', valid_roots)

r_values = []
s_values = []
for r in valid_roots:
	r = Integer(r)
	poly1305_1 = sum([coeffs_1[i] * r**(q-i) for i in range(q)]) % p
	poly1305_2 = sum([coeffs_2[i] * r**(q-i) for i in range(q)]) % p
	s1 = (a1 - poly1305_1) % int(2**128)
	s2 = (a2 - poly1305_2) % int(2**128)
	if s1 == s2:
		r_values.append(r)
		s_values.append(s1)
print('r_values', r_values)
print('s_values', s_values)


#######################
### Message Forgery ###
#######################

# Now attempt to forge a new message using candidate (r,s) pairs

# Since both the nonce and key are reused, and we know both the plaintext
# and ciphertext, we can directly recover the keystream via XOR and use this
# to encrypt arbitrary messages
key1 = byte_xor(pkt1, ct1)
key2 = byte_xor(pkt2, ct2)
assert(key1 == key2)
assert(len(key1) == 48)
key = key1

# Encrypt a 3rd adversarial message packet
pkt3 = bytearray(
	bytes([int(x) for x in ip_dot_3.split(".")]) +
	bytes([int(x) for x in gateway_ip.split(".")]) +
	bytes([255, 255, 255, 0]) +
	bytes([int(x) for x in own_ip_address.split(".")]) +
	bytes([int(x) for x in own_ip_address.split(".")]) +
	b'\x00'*12 +
	b'\x02'*15 +
	b"\x00"
)
assert(len(pkt3) == 48)
ct3 = byte_xor(pkt3, key)
nonce3 = nonce2
print(f'ct3 = {ct3.hex()}')
print(f'nonce3 = {nonce3.hex()}')


# Create forged authentication tag

# https://datatracker.ietf.org/doc/html/rfc7539#section-2.8 
msg3 = ct3 + b'\x00'*8 + long_to_bytes(len(ct3)) + b'\x00'*7
assert(len(msg3) % 16 == 0)
assert(len(msg3) == 64)

# https://en.wikipedia.org/wiki/Poly1305
p = 2**130 - 5
L = len(msg3)
q = L // 16
assert(q == 4)

m3_chunks = [msg3[i*16:i*16+16] + b'\x01' for i in range(q)]

coeffs_3 = []
for i in range(q):
	k = 0
	c_i_3 = 0
	for j in range(0, 128+1, 8):
		c_i_3 += m3_chunks[i][k] * 2**j
		k += 1
	coeffs_3.append(c_i_3)

# Try all candidate (r,s) pairs
for i in range(len(r_values)):
	r = r_values[i]
	s = s_values[i]
	print(f'i = {i}')
	print(f'--> r = {r}')
	print(f'--> s = {s}')
	poly1305_3 = sum([coeffs_3[i] * r**(q-i) for i in range(q)]) % p
	a3 = (poly1305_3 + s) % 2**128
	tag3 = int(a3).to_bytes(16, byteorder='little')
	crc3 = calc_crc(pkt3)
	pkt3 = ct3 + tag3 + nonce3 
	# Attempt to send this packet to the FlagServer for decryption:
	message_to_flag_server = bytearray(
		dhcp_server_mac + # src mac
		flag_server_mac + # dst mac
		b'\x02' +
		pkt3 +
		crc3
	)
	send_message_to_flag_server(message_to_flag_server)
	# Tell the FlagServer to broadcast the flag:
	print('Make FlagServer transmit the flag to (- what they think is -) http://example.com/{flag}')
	message_to_flag_server = bytearray(
		dhcp_server_mac + # src mac
		flag_server_mac + # dst mac
		b'\x03'
	)
	send_message_to_flag_server(message_to_flag_server)

conn.close()
