from encryption import AESCBCCipher
from Crypto.Random import get_random_bytes

class VaudenayAttack:
  def __init__(self, oracle: object):
    """
    Initialize the attack with a padding oracle.

    Parameters
    ----------
    oracle : object
        An object implementing:
          - get_ciphertext() -> bytes: returns the ciphertext (IV || body) to attack
          - query(ciphertext: bytes) -> bool: returns True if padding valid
    """
    self._oracle = oracle
    self._query_cache = {}

  def cached_query(self, ciphertext: bytes) -> bool:
    if ciphertext in self._query_cache:
      return self._query_cache[ciphertext]
    result = self._oracle.query(ciphertext)
    self._query_cache[ciphertext] = result
    return result

  def get_ciphertext(self) -> bytes:
    """
    Fetch the target ciphertext from the oracle.

    Returns
    -------
    bytes
        The ciphertext, with the IV prepended, that the attack will recover.
    """
    return self._oracle.get_ciphertext()

  def query(self, ciphertext: bytes) -> bool:
    """
    Query the oracle to test padding validity.

    Parameters
    ----------
    ciphertext : bytes
        Ciphertext (IV || body) to submit to the padding oracle.

    Returns
    -------
    bool
        True if the decrypted plaintext has valid PKCS#7 padding; False otherwise.
    """
    return self.cached_query(ciphertext)

  def last_word(self, ct: bytes) -> bytes:
    """
    Implements section 3.1 of the Vaudenay paper to recover the last byte
    of the plaintext block corresponding to ciphertext block `ct`.
    """
    oracle = self._oracle.query

    # Step 1: pick a random 16-byte block R
    R = get_random_bytes(16)
    

    # Step 2-4: find rb such that O(R[:15] + (rb ^ i) | ct) returns 1
    for i in range(256):
      r_mutable = bytearray(R)
      r_mutable[-1] = R[-1] ^ i
      r = bytes(r_mutable)
      if oracle(r + ct) == 1:
        break

    # Step 5: Check if padding is longer than 0x01
    for n in range(16, 1, -1):
      r_mutable = bytearray(r)
      r_mutable[16 - n] ^= 1  # flip the nth-from-last byte
      r_test = bytes(r_mutable)
      if oracle(r_test + ct) == 0:
        # Found padding length = n
        result = bytes([r[k] ^ n for k in range(16 - n, 16)])
        return result[-1:]  # return only the last byte

    # Step 6: assume padding was 0x01
    return bytes([r[-1] ^ 1])

  def decrypt_block(self, ct: bytes) -> bytes:
    """
    Given a ciphertext block `ct` and a padding oracle,
    return D_K(ct) (i.e., the decryption of the block before XOR with IV).
    
    You must send a forged IV || ct to the oracle.
    """
    starting_iv = [0] * 16  # Will store D_K(ct)
    oracle = self._oracle.query

    for pad_val in range(1, 17):
        # Forge a block that will decrypt to padding ending in pad_val
        padding_iv = [pad_val ^ b for b in starting_iv]
        
        for candidate in range(256):
            padding_iv[-pad_val] = candidate
            iv = bytes(padding_iv)
            if oracle(iv + ct):  # Feed IV || ct to oracle
                if pad_val == 1:
                    # Confirm it's not a false positive (like legit padding)
                    padding_iv[-2] ^= 1
                    if not oracle(bytes(padding_iv) + ct):
                        continue
                break
        else:
            raise Exception(f"No valid byte found for pad_val = {pad_val}")

        starting_iv[-pad_val] = candidate ^ pad_val

    return bytes(starting_iv)

  def request_ciphertext(self) -> bytes:
    """
    Retrieve the full ciphertext to be attacked.

    Returns
    -------
    bytes
        The full ciphertext (IV || body) to decrypt block by block.
    """
    return self._oracle.get_ciphertext()

  def decrypt_ciphertext(self) -> bytes:
    """
    Perform a full CBC decryption using this block decrypt method.

    Returns
    -------
    bytes
        The recovered, unpadded plaintext for the oracle's ciphertext.

    Notes
    -----
    This method should:
      1. Call `self.request_ciphertext()` to get the data.
      2. Instantiate `AESCBCCipher(self.decrypt_block)`.
      3. Return `AESCBCCipher.decrypt(...)` on the full ciphertext.
    """
    full_ct = self.request_ciphertext()
    cbc = AESCBCCipher(self.decrypt_block)  # assumes AESCBCCipher is in scope
    return cbc.decrypt(full_ct)

if __name__=="__main__":
  from oracles import *
  attacker = VaudenayAttack(oracle)
  recovered_plaintext = attacker.decrypt_ciphertext()
  print(recovered_plaintext)