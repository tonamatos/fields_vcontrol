class AESCBCCipher:
	def __init__(self, block_decryptor):
		self.block_decrypt = block_decryptor

	def decrypt(self, ciphertext: bytes) -> bytes:
		"""
		Decrypts `ciphertext` under CBC. The IV is assumed to be the first 16 bytes of the ciphertext
		Returns the plaintext with PKCS#7 padding removed.
		"""
		return b'0'