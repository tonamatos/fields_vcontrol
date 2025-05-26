from typing import Callable
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class VaudenayOracle:
    def __init__(self,
                 query_fn: Callable[[bytes], bool],
                 get_ciphertext_fn: Callable[[], bytes]):
        """
        A generic CBC padding oracle interface.

        Parameters
        ----------
        query_fn : Callable[[bytes], bool]
            A callable that takes ciphertext bytes (IV prepended or however formatted)
            and returns True if padding is valid, False otherwise.
        get_ciphertext_fn : Callable[[], bytes]
            A callable that returns the target ciphertext to attack (including prepended IV).
        """
        self._query_fn = query_fn
        self._get_ciphertext_fn = get_ciphertext_fn

    def query(self, ciphertext: bytes) -> bool:
        """
        Ask the oracle whether `ciphertext` decrypts to validly-padded plaintext.

        Parameters
        ----------
        ciphertext : bytes
            The ciphertext to test (IV prepended, or as expected by the oracle).

        Returns
        -------
        bool
            True if padding is valid; False otherwise.
        """
        return self._query_fn(ciphertext)

    def get_ciphertext(self) -> bytes:
        """
        Retrieve the ciphertext to attack.

        Returns
        -------
        bytes
            The ciphertext (including IV) that the attack should target.
        """
        return self._get_ciphertext_fn()

if __name__=="__main__":
  # 1) Create a key & some plaintext, then encrypt it under AES-CBC + PKCS#7
  key       = get_random_bytes(16)
  plaintext = b"Attack at dawn! Here's some test data."
  iv        = get_random_bytes(16)
  cipher_enc = AES.new(key, AES.MODE_CBC, iv=iv)
  ciphertext_body = cipher_enc.encrypt(pad(plaintext, AES.block_size))
  test_ciphertext = iv + ciphertext_body

  # 2) Define the local oracle functions
  def local_query(ct: bytes) -> bool:
    """Return True if ct decrypts to correctly-padded plaintext."""
    iv_, body = ct[:16], ct[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv_)
    pt_padded = cipher.decrypt(body)
    try:
      unpad(pt_padded, AES.block_size)
      return True
    except ValueError:
      return False

  def local_get_ciphertext() -> bytes:
    """Return the precomputed ciphertext to attack."""
    return test_ciphertext

  # 3) Instantiate and exercise the oracle
  oracle = VaudenayOracle(query_fn=local_query,
                          get_ciphertext_fn=local_get_ciphertext)

  ciphertext = oracle.get_ciphertext()
  print("Original padding valid? ", oracle.query(ciphertext))        # → True

  # 4) Tamper with one byte and see padding fail
  tampered = bytearray(ciphertext)
  tampered[63] ^= 0xFF    #Tamper the last byte to increase chances of failure
  print("After bit-flip padding valid?", oracle.query(bytes(tampered)))  # → False