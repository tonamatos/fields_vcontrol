BLOCK_SIZE = 16  # AES block size in bytes

def pad_msg(msg: bytes) -> bytes:
    '''
    Applies PKCS#7 padding to the message so its length is a multiple of 16.
    '''
    pad_len = BLOCK_SIZE - (len(msg) % BLOCK_SIZE)
    padding = bytes([pad_len] * pad_len)
    return msg + padding

def check_padding(padded_msg: bytes) -> bool:
    '''
    Verifies if the input has valid PKCS#7 padding.
    Returns True if valid, False otherwise.
    '''
    if not padded_msg or len(padded_msg) == 0:
        return False

    pad_len = padded_msg[-1]

    # Padding length must be between 1 and BLOCK_SIZE
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        return False

    # The last pad_len bytes must all be the same value
    if padded_msg[-pad_len:] != bytes([pad_len] * pad_len):
        return False

    return True

def unpad_msg(padded_msg: bytes) -> bytes:
    '''
    Removes PKCS#7 padding if valid. Raises ValueError if padding is invalid.
    '''
    if not check_padding(padded_msg):
        raise ValueError("Invalid PKCS#7 padding.")
    
    pad_len = padded_msg[-1]
    return padded_msg[:-pad_len]


if __name__ == "__main__":
    original = b"Secret message"
    print("")
    padded = pad_msg(original)
    print(padded)
    print(check_padding(padded))
    unpadded = unpad_msg(padded)
    print(unpadded)