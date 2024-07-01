import json
from packages.utils.src.crypto_utils import check_address
from packages.utils.src.SDKErrors import Errors
from ss58_format import ss58_format

def flatten_object(obj, prefix=''):
    """
    Flattens a nested dictionary.

    :param obj: The dictionary to flatten.
    :param prefix: The prefix to use for the keys.
    :return: A flattened dictionary.
    """
    flat_object = {}

    for key in obj:
        new_key = f'{prefix}{key}'

        if isinstance(obj[key], dict) and obj[key] is not None and not isinstance(obj[key], list):
            deeper = flatten_object(obj[key], f'{new_key}.')
            flat_object.update({new_key: obj[key]}, **deeper)
        else:
            flat_object[new_key] = obj[key]

    return flat_object


def extract_key_part_from_statement(statement: str) -> str | None:
    try:
        obj = json.loads(statement)
        keys = list(obj.keys())
        if keys:
            # Always retain 'issuer' and 'holder'
            if keys[0] == 'issuer' or keys[0] == 'holder':
                return keys[0]
            
            parts = keys[0].split('#')
            return parts[1] if len(parts) > 1 else None
        return None
    except (json.JSONDecodeError, TypeError):
        return None  # If parsing fails, return null


def filter_statements(statements, selected_attributes):
    filtered_statements = []
    for statement in statements:
        key_part = extract_key_part_from_statement(statement)
        if key_part:
            if key_part == 'issuer' or key_part == 'holder' or key_part in selected_attributes:
                filtered_statements.append(statement)
    return filtered_statements


def verify_cord_address(input) -> None:
    """
    Verifies a given address string against the External Address Format (SS58) with our Prefix of 29.

    @param input: Address string to validate for correct format.
    """
    if not isinstance(input, str):
        raise Errors.AddressTypeError()
    if not check_address(input, ss58_format):
        raise Errors.AddressInvalidError(input)
    

