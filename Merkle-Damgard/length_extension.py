def url_format(data: bytes) -> str:
    """
    Convert a bytes sequence to its URL-encoded representation by percent-encoding each byte.

    Each byte in the input is formatted as a two-digit hexadecimal number,
    prefixed with '%', as commonly used in URL encoding.

    Args:
        data (bytes): The input data to encode.

    Returns:
        str: A string where each byte of `data` is represented as '%XX',
             with XX being the lowercase hexadecimal value of the byte.

    Example:
        >>> url_format(b'Hello!')
        '%48%65%6c%6c%6f%21'
    """
    return ''.join(f'%{byte:02x}' for byte in data)

import hashlib
import base64

def compute_hash(message: bytes, algorithm='sha256', output_format='hex'):
    '''
    Parameters
    ----------
    algorithm : str
        Must be one of the following algorithms: 
	    1. 'md5'
	    2. 'sha256'
	    3. 'sha512'
	
	    Otherwise throws an error. 
    message : bytes (or bytes-like object)
        Encoded message to be hashed with the given algorithm. 
	output_format : str
		Must be one of the following: 
		i. 'bytes'
	    ii. 'hex'
		iii. base64

		Otherwise throws an error
		
    Returns
    -------
	The hash digest of message, using the given algorithm, in the given format. If 'bytes', will return a bytes object. If 'hex' or 'base64' will return a string of the given encoding. 
    '''
    # Select algorithm
    if not algorithm in ['md5','sha256','sha512']:
        raise ValueError("Invalid algorithm",algorithm)
    hash_func = {'md5'   : hashlib.md5,
                 'sha256': hashlib.sha256,
                 'sha512': hashlib.sha512}[algorithm]()
    
    # Update hash with message
    hash_func.update(message)
    digest_bytes = hash_func.digest()

    # Select format output
    if output_format == 'bytes':
        return digest_bytes
    elif output_format == 'hex':
        return digest_bytes.hex()
    elif output_format == 'base64':
        return base64.b64encode(digest_bytes).decode('utf-8')
    else:
        raise ValueError("Unsupported output format", output_format)

import struct

def compute_padding(message: bytes, algorithm='sha256', output_format='hex'):
    """
    Parameters
    ----------
    algorithm : str
        One of: 'md5', 'sha256', 'sha512'
    message : bytes
        Data to hash. Required.
    output_format : str
        One of: 'bytes', 'hex', 'base64'
    
    Returns
    -------
    bytes or str
        The padding that the given algorithm adds to the message before processing. To be used in implementation of the length extension attack. 
    """
    message_bit_length = len(message) * 8 # Message length in bits

    # Step 1: Append 1 bit as a full byte (0x80)
    padding = b'\x80'

    # Determine block size and length field size for each algorithm
    if algorithm == 'md5':
        block_size = 64       # 512 bits
        length_field_size = 8 # 64-bit little-endian
        length_bytes = struct.pack('<Q', message_bit_length)

    elif algorithm == 'sha256':
        block_size = 64       # 512 bits
        length_field_size = 8 # 64-bit big-endian
        length_bytes = struct.pack('>Q', message_bit_length)

    elif algorithm == 'sha512':
        block_size = 128       # 1024 bits
        length_field_size = 16 # 128-bit big-endian
        length_bytes = struct.pack('>QQ', 0, message_bit_length)

    # Step 2: Pad with zeros until message length = (block_size - length_field_size) mod block_size
    total_len = len(message) + 1  # original + 0x80
    padding_len = (block_size - length_field_size - total_len % block_size) % block_size
    padding += b'\x00' * padding_len

    # Step 3: Append the length field
    padding += length_bytes

    # Output formatting
    if output_format == 'bytes':
        return padding
    elif output_format == 'hex':
        return padding.hex()
    elif output_format == 'base64':
        return base64.b64encode(padding).decode('utf-8')

if __name__ == "__main__":

    message = b'This message is to test the hereby defined functions.'
    print("URL format:", url_format(message))
    print()
    print("Hash SHA256 in base64:",compute_hash(message, output_format='base64'))
    print("Hash SHA256 in hex:",compute_hash(message, output_format='hex'))
    print()
    print("Padding SHA256 in base64:",compute_padding(message, output_format='base64'))
    print("Padding SHA256 in hex:",compute_padding(message, output_format='hex'))

    # A good tool to double check these things is https://stepansnigirev.github.io/visual-sha256/