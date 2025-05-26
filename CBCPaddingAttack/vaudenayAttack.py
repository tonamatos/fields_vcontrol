from typing import Callable, Optional
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
    return self._oracle.query(ciphertext)

  def last_word(self, ct: bytes) -> bytes:
    """
    Implements section 3.1 of the Vaudenay paper.
    """
    oracle = self._oracle
    r = get_random_bytes(16)
    i = 0
    while oracle(r + ct) == 0:
      i += 1


  def decrypt_block(self, ct: bytes) -> bytes:
    """
    Recover a single plaintext block via the padding oracle.

    Parameters
    ----------
    ct : bytes
        A 16-byte ciphertext block to decrypt.

    Returns
    -------
    bytes
        The 16-byte plaintext block corresponding to `ct`.
    """


    

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