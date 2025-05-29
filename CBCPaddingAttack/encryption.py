# The most up-to-date version of this code is found in https://github.com/tonamatos/fields_vcontrol

from padding import unpad_msg

class AESCBCCipher:
	def __init__(self, block_decryptor):
		self.block_decrypt = block_decryptor

	def decrypt(self, ciphertext: bytes, unpad=False) -> bytes:
		"""
		Decrypts `ciphertext` under CBC. The IV is assumed to be the first 16 bytes of the ciphertext
		Returns the plaintext with PKCS#7 padding removed.
		"""
		if len(ciphertext) < 16 or len(ciphertext) % 16 != 0:
			raise ValueError("Ciphertext must be a multiple of 16 bytes and include an IV")

		iv = ciphertext[:16] # Use assumption to extract IV
		ciphertext_blocks = [ciphertext[i:i+16] for i in range(16, len(ciphertext), 16)]
		previous_block = iv # Need to keep track of the current and the previous, since they are chained
		plaintext = b''

		for block in ciphertext_blocks:
			decrypted_block = self.block_decrypt(block)
			plaintext_block = bytes(a ^ b for a, b in zip(decrypted_block, previous_block)) # XOR
			plaintext += plaintext_block
			previous_block = block

		if unpad:
			return unpad_msg(plaintext)
		return plaintext

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def aes_block_decrypt(key: bytes, block: bytes) -> bytes:
	"""
	Decrypt exactly one 16-byte block under AES-ECB.
	
	Parameters
	----------
	key : bytes 
		16, 24, or 32-byte AES key
	block : bytes
		16-byte ciphertext block
	
	Returns
	------- 
	bytes
	16-byte plaintext block
	"""
	if len(block) != AES.block_size:
		raise ValueError(f"Ciphertexttext block must be {AES.block_size} bytes")
	if len(key) not in {16, 24, 32}:
		raise ValueError("AES key must be 16, 24, or 32 bytes")
	cipher = AES.new(key, AES.MODE_ECB)
	return cipher.decrypt(block)


def aes_cbc_encrypt(key: bytes, message: bytes) -> bytes:
	iv = get_random_bytes(AES.block_size)
	cipher = AES.new(key, AES.MODE_CBC, iv)
	return iv + cipher.encrypt(pad(message, AES.block_size))

def test_cbc():
	key = bytes(16)
	messages = [b"a sample message that's more than a block", b"a sample message", b"short"]
	decryptor = (lambda block: aes_block_decrypt(key, block)) 
	cbc_cipher = AESCBCCipher(decryptor)

	for m in messages: 
		ctxt = aes_cbc_encrypt(key, m)
		assert cbc_cipher.decrypt(ctxt) == m

	print("All assertions passed!")

if __name__ == "__main__":
	test_cbc()