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
    u8a_to_u8a,
)

from packages.utils.src.idents import (
    SPACE_IDENT,
    SCHEMA_IDENT,
    STATEMENT_IDENT,
    RATING_IDENT,
    AUTH_IDENT,
    ACCOUNT_IDENT,
    ASSET_IDENT,
    ASSET_INSTANCE_IDENT,
)

from packages.utils.src.prefix import (
    SPACE_PREFIX,
    SCHEMA_PREFIX,
    STATEMENT_PREFIX,
    RATING_PREFIX,
    AUTH_PREFIX,
    ACCOUNT_PREFIX,
    ASSET_PREFIX,
)

from packages.utils.src.SDKErrors import Errors

VALID_IDENTS = {
    SPACE_IDENT,
    SCHEMA_IDENT,
    STATEMENT_IDENT,
    RATING_IDENT,
    AUTH_IDENT,
    ACCOUNT_IDENT,
    ASSET_IDENT,
    ASSET_INSTANCE_IDENT,
}

VALID_PREFIXES = [
    SPACE_PREFIX,
    SCHEMA_PREFIX,
    STATEMENT_PREFIX,
    RATING_PREFIX,
    AUTH_PREFIX,
    ACCOUNT_PREFIX,
    ASSET_PREFIX,
]

IDENT_TO_PREFIX_MAP = {
    SPACE_IDENT: SPACE_PREFIX,
    SCHEMA_IDENT: SCHEMA_PREFIX,
    STATEMENT_IDENT: STATEMENT_PREFIX,
    RATING_IDENT: RATING_PREFIX,
    AUTH_IDENT: AUTH_PREFIX,
    ACCOUNT_IDENT: ACCOUNT_PREFIX,
    ASSET_IDENT: ASSET_PREFIX,
    ASSET_INSTANCE_IDENT: ASSET_PREFIX,
}

defaults = {
    "allowed_decoded_lengths": [1, 2, 4, 8, 32, 33],
    "allowed_encoded_lengths": [3, 4, 6, 10, 35, 36, 37, 38],
}

IDFR_PREFIX = string_to_u8a("CRDIDFR")


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
        iDfrDecoded = (
            ((decoded[0] & 0b00111111) << 2)
            | (decoded[1] >> 6)
            | ((decoded[1] & 0b00111111) << 8)
        )

    # Check if the length indicates a content hash (34/35 bytes + prefix)
    isContentHash = (len(decoded) == 34 + iDfrLength) or (
        len(decoded) == 35 + iDfrLength
    )
    length = len(decoded) - (2 if isContentHash else 1)

    # Calculate the hash for checksum verification
    hash_value = pphash(decoded[:length])

    # Validate the checksum
    isValid = (
        (decoded[0] & 0b10000000) == 0
        and decoded[0] not in [46, 47]
        and (
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
    assert_condition(key, "Invalid key string passed")

    # Decode the key to byte array, allowing re-encoding of an identifier
    u8a = u8a_to_u8a(key)

    # Validate the identifier prefix
    assert_condition(
        0 <= iDPrefix <= 16383 and iDPrefix not in [46, 47],
        "Out of range IdentifierFormat specified",
    )

    # Validate the length of the decoded key
    assert_condition(
        len(u8a) in defaults["allowed_decoded_lengths"],
        f"Expected a valid key to convert, with length {', '.join(map(str, defaults['allowed_decoded_lengths']))}",
    )

    # Prepare the input with the identifier prefix
    if iDPrefix < 64:
        prefix = bytes([iDPrefix])
    else:
        prefix = bytes(
            [
                ((iDPrefix & 0b000011111100) >> 2) | 0b01000000,
                (iDPrefix >> 8) | ((iDPrefix & 0b000000000011) << 6),
            ]
        )

    input_data = u8a_concat(prefix, u8a)

    # Encode the input with base58, including the checksum
    return base58_encode(
        u8a_concat(input_data, pphash(input_data)[: 2 if len(u8a) in [32, 33] else 1])
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
    assert_condition(digest, "Invalid digest")
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
    ```
    digest = '0x1234...'; # Hex string or byte array or regular string
    uri = hash_to_uri(digest, 29, 'example:')
    print('URI:', uri)
    ```

    :raises: ValueError if the digest is invalid.
    """
    assert_condition(digest, "Invalid digest")
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
    assert_condition(digest, "Invalid digest")
    id = encode_identifier(digest, iDPrefix)
    return f"{prefix}{id}:{digest}"


def check_identifier(identifier):
    """
    Validates an identifier by decoding and checking its integrity.

    This function takes an identifier, typically encoded in base58 format, and performs a series of checks to validate it.
    These checks include decoding the identifier, verifying its checksum, length, and prefix against predefined standards.

    :param identifier: The identifier to be validated, provided as a hex string or a regular string.
    :return: A tuple where the first element is a boolean indicating the validity of the identifier,
             and the second element is a string containing an error message if the identifier is invalid.

    :example:
    identifier = 'base58EncodedIdentifier'
    is_valid, error = check_identifier(identifier)
    if is_valid:
        print('Identifier is valid')
    else:
        print('Invalid identifier:', error)

    :description:
    The function attempts to decode the given identifier from its base58 format. If the decoding fails,
    it returns False along with the error message. It then checks the identifier's checksum, length, and prefix.
    If these checks pass, the function confirms the identifier's validity. Otherwise, it returns False with an
    appropriate error message describing the failure reason.
    """
    try:
        decoded = base58_decode(identifier)
    except ValueError as error:
        return False, str(error)

    is_valid, _, _, idfr_decoded = check_identifier_checksum(decoded)

    if idfr_decoded in VALID_IDENTS:
        if len(decoded) not in defaults["allowedEncodedLengths"]:
            return False, "Invalid decoded identifier length"
        return is_valid, None if is_valid else "Invalid decoded identifier checksum"

    return False, f"Prefix mismatch, found {idfr_decoded}"


def is_valid_identifier(input):
    """
    Validates the format and structure of an identifier, checking its prefix and overall validity.

    This function assesses whether the provided input is a valid identifier, conforming to specific format and encoding rules.
    It checks if the input starts with any known valid prefixes and, if found, strips the prefix before further validation.
    The function then employs `check_identifier` to perform a comprehensive validation of the identifier.

    :param input: The identifier to be validated, provided as a hex string or a regular string.
    :return: A tuple where the first element is a boolean indicating the overall validity of the identifier,
             and the second element is a string containing an error message if the identifier is invalid.

    :example:
    input = 'prefix1234Base58EncodedString'
    is_valid, error = is_valid_identifier(input)
    if is_valid:
        print('Valid identifier')
    else:
        print('Invalid identifier:', error)
    """
    identifier = input
    found_prefix = next(
        (prefix for prefix in VALID_PREFIXES if input.startswith(prefix)), None
    )

    if found_prefix:
        identifier = input[len(found_prefix) :]

    is_valid, error_message = check_identifier(identifier)
    return is_valid, error_message


def uri_to_identifier(uri):
    """
    Converts a URI to a valid identifier by checking its format and stripping known prefixes.

    This function processes a URI and transforms it into a valid identifier. It validates the URI's format,
    checks for known prefixes, and ensures the resulting string conforms to identifier standards.

    :param uri: The URI to be converted into an identifier. Can be a string, None, or undefined.
    :return: The validated identifier as a string.
    :raises InvalidURIError: If the input is not a string or is empty.
    :raises InvalidIdentifierError: If the processed identifier is invalid, with a detailed error message.
    """
    if not isinstance(uri, str) or not uri:
        raise Errors.InvalidURIError("URI must be a non-empty string.")

    identifier = uri
    found_prefix = next(
        (prefix for prefix in VALID_PREFIXES if uri.startswith(prefix)), None
    )

    if found_prefix:
        identifier = uri[len(found_prefix) :]

    is_valid, error_message = check_identifier(identifier)

    if not is_valid:
        raise Errors.InvalidIdentifierError(
            error_message or f"Invalid identifier: {uri}"
        )

    return identifier


def identifier_to_uri(identifier: str) -> str:
    """
    Transforms a given identifier into a URI by appending a relevant prefix, if necessary.

    This function takes a string identifier, validates it, and converts it into a URI by appending a suitable prefix.
    It also checks if the identifier already has a valid prefix and, if so, returns it unchanged.

    :param identifier: The identifier string to be transformed into a URI.
    :return: A string representing the URI constructed from the identifier.

    :raises Errors.SDKError: If the input is not a non-empty string, if the identifier's checksum is invalid,
                             if the identifier is unrecognized, or if there is an error during decoding.
    
    :example:
    ```python
    try:
        identifier = 'base58EncodedIdentifier'  # Replace with actual base58 encoded identifier
        uri = identifier_to_uri(identifier)
        print(f'URI: {uri}')
    except Errors.SDKError as e:
        print(f'Error Type: {type(e).__name__}')
        print(f'Error Message: {e}')
    ```
    """
    if not isinstance(identifier, str) or len(identifier) == 0:
        raise Errors.SDKError('Input must be a non-empty string.')

    # Check if the input is already a URI
    existing_prefix = next((prefix for prefix in VALID_PREFIXES if identifier.startswith(prefix)), None)
    if existing_prefix is not None:
        return identifier  # Return as is, since it's already a URI

    # Attempt to decode the identifier and extract the prefix
    try:
        decoded = base58_decode(identifier)
        is_valid, _, _, idfr_decoded = check_identifier_checksum(decoded)
        if not is_valid:
            raise Errors.InvalidIdentifierError('Invalid decoded identifier checksum')

        ident = idfr_decoded
        prefix = IDENT_TO_PREFIX_MAP.get(ident)
        if not prefix:
            raise Errors.InvalidIdentifierError(f'Invalid or unrecognized identifier: {ident}')

        # Construct and return the URI
        return f"{prefix}{identifier}"
    except Exception as error:
        raise Errors.InvalidIdentifierError(f'Error decoding identifier: {str(error)}')

def get_account_identifier_from_address(address: str) -> str:
    """
    Creates an account identifier from a given account address.

    This function takes an account address and appends a predefined prefix (if not already present)
    to generate a standardized account identifier. It ensures that all account identifiers
    have a consistent format.

    :param address: The account address used to derive the identifier.
    :return: The account identifier, which is the address prefixed with a standard identifier prefix.

    :example:
    ```python
    account_address = '0x1234...'
    identifier = get_account_identifier_from_address(account_address)
    print(f'Account Identifier: {identifier}')
    ```
    """
    return address if address.startswith(ACCOUNT_PREFIX) else ACCOUNT_PREFIX + address

def get_account_address_from_identifier(identifier: str) -> str:
    """
    Derives an account address from a given account identifier.

    This function extracts the actual account address from an identifier by removing the standard prefix.
    It assumes that the identifier begins with a predefined prefix and strips it to retrieve the original address.

    :param identifier: The account identifier from which to derive the address.
    :return: The original account address, derived by removing the standard prefix from the identifier.

    :example:
    ```python
    account_identifier = 'prefix0x1234...'
    try:
        account_address = get_account_address_from_identifier(account_identifier)
        print(f'Account Address: {account_address}')
    except ValueError as error:
        print(f'Error: {error}')
    ```

    :raises ValueError: If the identifier does not start with the defined `ACCOUNT_PREFIX`.
    """
    if not identifier.startswith(ACCOUNT_PREFIX):
        raise ValueError(f"Identifier does not start with the defined prefix: {ACCOUNT_PREFIX}")
    
    return identifier[len(ACCOUNT_PREFIX):]

def build_statement_uri(id_digest: str, digest: str) -> str:
    """
    Constructs a statement URI from given hexadecimal string digests.

    This function generates a standardized URI for a statement by combining a hashed identifier digest
    and another digest. The identifier digest is first converted to a URI with a specific prefix, and
    then concatenated with the sliced second digest to form the complete statement URI.

    :param id_digest: A hexadecimal string representing the identifier digest. Must start with '0x'.
    :param digest: Another hexadecimal string representing the statement's content digest. Must also start with '0x'.
    :return: A `StatementUri` representing the combined URI for the statement.

    :example:
    ```python
    id_digest = '0x1234...'
    digest = '0xabcd...'
    statement_uri = build_statement_uri(id_digest, digest)
    print('Statement URI:', statement_uri)
    ```

    :raises InvalidInputError: If either `id_digest` or `digest` does not start with '0x'.
    """
    if not digest.startswith('0x') or not id_digest.startswith('0x'):
        raise Errors.InvalidInputError('Digest must start with 0x')
    
    prefix = hash_to_uri(id_digest, STATEMENT_IDENT, STATEMENT_PREFIX)
    suffix = digest[2:]

    statement_uri = f"{prefix}:{suffix}"
    return statement_uri

def update_statement_uri(stmt_uri: str, digest: str) -> str:
    """
    Updates the digest component of a given statement URI with a new digest.

    This function modifies an existing statement URI by replacing its digest with a new provided digest.
    It ensures that the URI retains its original structure and prefix, while only the digest part is updated.

    :param stmt_uri: The original statement URI that needs to be updated. It should follow the format 'stmt:cord:<identifier>:<digest>'.
    :param digest: The new hexadecimal string digest to be inserted into the statement URI. Must start with '0x'.
    :return: The updated statement URI, now containing the new digest.

    :example:
    ```python
    original_uri = 'stmt:cord:1234:abcd'
    new_digest = '0x5678...'
    updated_uri = update_statement_uri(original_uri, new_digest)
    print('Updated Statement URI:', updated_uri)
    ```

    :raises InvalidIdentifierError: If the `stmt_uri` does not follow the expected format.
    :raises InvalidInputError: If the new `digest` does not start with '0x'.
    """
    parts = stmt_uri.split(':')

    if len(parts) != 4 or parts[0] != 'stmt' or parts[1] != 'cord':
        raise Errors.InvalidIdentifierError('Invalid statementUri format')

    if not digest.startswith('0x'):
        raise Errors.InvalidInputError('Digest must start with 0x')

    suffix = digest[2:]
    statement_uri = f'stmt:cord:{parts[2]}:{suffix}'
    return statement_uri

def uri_to_statement_id_and_digest(statement_uri: str) -> dict:
    """
    Extracts the statement identifier and digest from a given statement URI.

    This function parses a statement URI and separates it into its constituent identifier and digest components.
    It expects the URI to conform to a specific format and structure.

    :param statement_uri: The statement URI to be parsed. Expected format: 'stmt:cord:<identifier>:<digest>'.
    :return: A dictionary containing the extracted identifier and digest from the statement URI.

    :example:
    ```python
    statement_uri = 'stmt:cord:1234:abcd'
    result = uri_to_statement_id_and_digest(statement_uri)
    print('Identifier:', result['identifier'], 'Digest:', result['digest'])
    ```

    :raises InvalidIdentifierError: If the `statement_uri` does not follow the expected format.
    """
    parts = statement_uri.split(':')

    if len(parts) != 4 or parts[0] != 'stmt' or parts[1] != 'cord':
        raise Errors.InvalidIdentifierError('Invalid statementUri format')

    identifier = parts[2]
    suffix = parts[3]

    digest = f'0x{suffix}'

    return {'identifier': identifier, 'digest': digest}

def element_uri_to_statement_uri(statement_uri: str) -> str:
    """
    Converts a given element URI to a statement URI.

    This function processes an element URI and reformats it to construct a corresponding statement URI.
    It expects the element URI to follow a specific format and extracts the relevant part to create the statement URI.

    :param statement_uri: The element URI to be converted. Expected format: 'stmt:cord:<identifier>:<digest>'.
    :return: A statement URI derived from the element URI, excluding the digest component.

    :example:
    ```python
    element_uri = 'stmt:cord:1234:abcd'
    statement_id = element_uri_to_statement_uri(element_uri)
    print('Statement URI:', statement_id)
    ```

    :raises InvalidIdentifierError: If the `statement_uri` does not conform to the required format.
    """
    parts = statement_uri.split(':')

    if len(parts) != 4 or parts[0] != 'stmt' or parts[1] != 'cord':
        raise Errors.InvalidIdentifierError('Invalid statementUri format')

    identifier = parts[2]
    statement_id = f'stmt:cord:{identifier}'

    return statement_id