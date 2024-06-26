from packages.utils.src.crypto_utils import (
    blake2_as_hex,
    blake2_as_u8a,
    base58_encode,
    base58_decode,
    check_address,
    random_as_u8a,
    signature_verify,
    encode_address,
    decode_address,
    is_hex,
    hex_to_bn,
    string_to_u8a,
    u8a_concat,
    assert_condition,
    u8a_to_u8a
)

from packages.utils.src.SDKErrors import SDKError

defaults = {
    "allowed_decoded_lengths": [1, 2, 4, 8, 32, 33],
    "allowed_encoded_lengths": [3, 4, 6, 10, 35, 36, 37, 38],
}

IDFR_PREFIX = string_to_u8a('CRDIDFR')

def pphash(key):
    """
    Performs a post-processed hash on a given key.
    
    param key: The input data to be hashed, represented as a byte array.
    return: A byte array representing the 512-bit hash of the input key.
    """
    concatenated = u8a_concat(IDFR_PREFIX, key)
    return blake2_as_u8a(concatenated, 64)

def check_identifier_checksum(decoded):
    """
    Checks the checksum and decodes information from a given identifier.

    :param decoded: The decoded identifier represented as a byte array.
    :return: A tuple containing the validity of the identifier, its length, the identifier length, and its decoded value.
    """
    # Determine the length of the identifier (1 or 2 bytes based on the 7th bit)
    iDfrLength = 2 if (decoded[0] & 0b01000000) != 0 else 1

    # Decode the identifier from the first 1 or 2 bytes
    iDfrDecoded = decoded[0]
    if iDfrLength == 2:
        iDfrDecoded = ((decoded[0] & 0b00111111) << 2) | (decoded[1] >> 6) | ((decoded[1] & 0b00111111) << 8)

    # Check if the length indicates a content hash (34/35 bytes + prefix)
    isContentHash = (len(decoded) == 34 + iDfrLength) or (len(decoded) == 35 + iDfrLength)
    length = len(decoded) - (2 if isContentHash else 1)

    # Calculate the hash for checksum verification
    hash_value = pphash(decoded[:length])

    # Validate the checksum
    isValid = (
        (decoded[0] & 0b10000000) == 0 and
        decoded[0] not in [46, 47] and
        (
            (decoded[-2] == hash_value[0] and decoded[-1] == hash_value[1])
            if isContentHash
            else (decoded[-1] == hash_value[0])
        )
    )

    return isValid, length, iDfrLength, iDfrDecoded

def encode_identifier(key, iDPrefix):
    """
    Encodes a given key with a specified identifier prefix into a base58 encoded string.
    
    :param key: The key to be encoded, which can be a hex string, byte array, or a regular string.
    :param iDPrefix: The identifier prefix, a number that must be within the range of 0 to 16383 and
                     not equal to 46 or 47.
    :return: A base58 encoded string representing the encoded key with the identifier prefix and checksum.
    """
    assert_condition(key, 'Invalid key string passed')

    # Decode the key to byte array, allowing re-encoding of an identifier
    u8a = u8a_to_u8a(key)

    # Validate the identifier prefix
    assert_condition(
        0 <= iDPrefix <= 16383 and iDPrefix not in [46, 47],
        'Out of range IdentifierFormat specified'
    )

    # Validate the length of the decoded key
    assert_condition(
        len(u8a) in defaults["allowed_decoded_lengths"],
        f"Expected a valid key to convert, with length {', '.join(map(str, defaults['allowed_decoded_lengths']))}"
    )

    # Prepare the input with the identifier prefix
    if iDPrefix < 64:
        prefix = bytes([iDPrefix])
    else:
        prefix = bytes([
            ((iDPrefix & 0b000011111100) >> 2) | 0b01000000,
            (iDPrefix >> 8) | ((iDPrefix & 0b000000000011) << 6)
        ])

    input_data = u8a_concat(prefix, u8a)

    # Encode the input with base58, including the checksum
    return base58_encode(
        u8a_concat(
            input_data,
            pphash(input_data)[:2 if len(u8a) in [32, 33] else 1]
        )
    )
    
def hash_to_identifier(digest, iDPrefix):
    """
    Converts a digest to a unique identifier using a specified identifier prefix.

    :param digest: The input digest to be encoded, which can be a hex string, byte array, or a regular string.
    :param iDPrefix: The identifier prefix, a numerical value used to classify the type of data being encoded.
    :return: A string representing the encoded identifier.

    :example:
    digest = '0x1234...'; # Hex string or byte array or regular string
    identifier = hash_to_identifier(digest, 29)
    print('Identifier:', identifier)

    :raises: ValueError if the digest is invalid.
    """
    assert_condition(digest, 'Invalid digest')
    id = encode_identifier(digest, iDPrefix)
    return id

def hash_to_uri(digest, iDPrefix, prefix):
    """
    Converts a digest to a URI using a specified identifier prefix and a predefined prefix string.

    :param digest: The input digest to be encoded, which can be a hex string, byte array, or a regular string.
    :param iDPrefix: The identifier prefix, a numerical value used to classify the type of data being encoded.
    :param prefix: A predefined string prefix to be appended before the encoded identifier.
    :return: A string representing the URI constructed from the digest and identifier prefix.

    :example:
    digest = '0x1234...'; # Hex string or byte array or regular string
    uri = hash_to_uri(digest, 29, 'example:')
    print('URI:', uri)

    :raises: ValueError if the digest is invalid.
    """
    assert_condition(digest, 'Invalid digest')
    id = encode_identifier(digest, iDPrefix)
    return f"{prefix}{id}"

def hash_to_element_uri(digest, iDPrefix, prefix):
    """
    Converts a digest to an element URI using a specified identifier prefix and a predefined prefix string.

    :param digest: The input digest to be encoded, which can be a hex string, byte array, or a regular string.
    :param iDPrefix: The identifier prefix, a numerical value used to classify the type of data being encoded.
    :param prefix: A predefined string prefix to be appended before the encoded identifier and digest.
    :return: A string representing the element URI constructed from the digest, identifier prefix, and predefined prefix.

    :example:
    digest = '0x1234...'; # Hex string or byte array or regular string
    element_uri = hash_to_element_uri(digest, 42, 'element:')
    print('Element URI:', element_uri)

    :raises: ValueError if the digest is invalid.
    """
    assert_condition(digest, 'Invalid digest')
    id = encode_identifier(digest, iDPrefix)
    return f"{prefix}{id}:{digest}"