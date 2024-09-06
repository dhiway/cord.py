from packages.sdk.src import ConfigService, Did, Utils
from packages.identifier.src.identifier import (
    uri_to_identifier,
    build_statement_uri,
    uri_to_statement_id_and_digest,
    identifier_to_uri
)
from packages.utils.src.SDKErrors import Errors


def get_uri_for_statement(digest, space_uri, creator_uri):
    """
    Generates a unique URI for a statement based on its digest, space URI, and creator URI.

    This function constructs a statement URI by combining the provided digest with the identifiers
    of the space and the creator. It's a crucial function for creating a standard and unique identifier
    for statements on the CORD blockchain.

    Args:
        digest: The hexadecimal string representing the digest of the statement.
        spaceUri: The unique identifier of the space related to the statement.
        creatorUri: The decentralized identifier (DID) URI of the creator of the statement.

    Returns:
        The unique URI that represents the statement on the blockchain.

    Example:
        digest = '0x1234abcd...'
        spaceUri = 'space:cord:example_uri'
        creatorUri = 'did:cord:creator_uri'

        statement_uri = get_uri_for_statement(digest, spaceUri, creatorUri)
        print('Statement URI:', statement_uri)
    """

    api = ConfigService.get("api")

    scale_encoded_schema = api.encode_scale(
        type_string="H256", value=digest
    ).get_remaining_bytes()
    scale_encoded_space = api.encode_scale(
        type_string="Bytes", value=uri_to_identifier(space_uri)
    ).get_remaining_bytes()
    scale_encoded_creator = api.encode_scale(
        type_string="AccountId", value=Did.to_chain(creator_uri)
    ).get_remaining_bytes()

    concatenated_data = (
        scale_encoded_schema + scale_encoded_space + scale_encoded_creator
    )
    id_digest = "0x" + Utils.crypto_utils.blake2_as_hex(concatenated_data)

    return build_statement_uri(id_digest, digest)


async def is_statement_stored(digest: str, space_uri: str) -> bool:
    """
    Checks if a statement is stored on the CORD blockchain.

    Args:
        digest (str): The hexadecimal string representing the digest of the statement to check.
        space_uri (str): The unique identifier of the space where the statement is expected to be stored.

    Returns:
        bool: True if the statement is stored, or False otherwise.

    Example:
        digest = '0x1234abcd...'
        space_uri = 'space:cord:example_uri'

        is_stored = await is_statement_stored(digest, space_uri)
        if is_stored:
            print('Statement is stored on the blockchain.')
        else:
            print('Statement not found.')
    """

    api = ConfigService.get("api")
    space = uri_to_identifier(space_uri)
    encoded = api.query("Statement", "IdentifierLookup", [digest, space])

    return False if encoded.value is None else True


async def prepare_extrinsic_to_register(
    stmt_entry, creator_uri, author_account, authorization_uri, sign_callback
):
    """
    This function prepares and returns a SubmittableExtrinsic for registering a statement on the blockchain.

    Args:
        stmt_entry (dict): The stmtEntry parameter is a dictionary containing information about a statement entry.
        creator_uri (str): The creatorUri parameter is a URI that identifies the creator of the statement entry.
                           It is used to authorize the transaction when preparing the extrinsic.
        author_account (Keypair): The authorAccount parameter represents the keyring pair used for signing the extrinsic
                                  transaction. This keyring pair contains the cryptographic key pair necessary for signing
                                  and verifying messages.
        authorization_uri (str): The authorizationUri parameter is a URI that represents the authorization needed for
                                 the statement entry. It is used to identify and retrieve the authorization details required
                                 for registering the statement on the chain.
        sign_callback (function): The signCallback parameter is a callback function that is used to sign the extrinsic
                                  transaction before it is submitted to the blockchain. This function typically takes care
                                  of the signing process using the private key of the account that is authorizing the transaction.

    Returns:
        dict: A SubmittableExtrinsic is being returned from the prepare_extrinsic_to_register function.
    """
    try:
        api = ConfigService.get("api")

        authorization_id = uri_to_identifier(authorization_uri)
        schema_id = (
            uri_to_identifier(stmt_entry["schema_uri"])
            if "schema_uri" in stmt_entry
            else None
        )

        exists = await is_statement_stored(
            stmt_entry["digest"], stmt_entry["space_uri"]
        )

        if exists:
            raise Errors.DuplicateStatementError(
                f"The statement is already anchored in the chain\nIdentifier: {stmt_entry['element_uri']}"
            )

        tx = api.compose_call(
            call_module="Statement",
            call_function="register",
            call_params={
                "digest": stmt_entry["digest"],
                "authorization": authorization_id,
                "schema_id": schema_id if schema_id else None,
            },
        )

        # Authorize the transaction
        extrinsic = await Did.authorize_tx(
            creator_uri, tx, sign_callback, author_account.ss58_address
        )

        return extrinsic

    except Exception as error:
        raise Errors.CordDispatchError(f"Error returning extrinsic: {error}")


async def dispatch_register_to_chain(stmt_entry, creator_uri, author_account, authorization_uri, sign_callback):
    """
    This function dispatches a statement entry to a blockchain after preparing the extrinsic
    and signing it.

    Args:
        stmt_entry (dict): The statement entry object containing the necessary information for registering the statement on the blockchain.
        creator_uri (str): The DID URI of the creator of the statement. This identifier is used to authorize the transaction.
        author_account (Keypair): The blockchain account used to sign and submit the transaction.
        authorization_uri (str): The URI of the authorization used for the statement.
        sign_callback (function): A callback function that handles the signing of the transaction.

    Returns:
        str: The element URI of the registered statement.

    Raises:
        Exception: Raised when there is an error during the dispatch process.

    Example:
        stmt_entry = {
            # ... initialization of statement properties ...
        }
        creator_uri = 'did:cord:creator_uri'
        author_account = Keypair.create_from_uri('//Alice')
        authorization_uri = 'auth:cord:example_uri'
        sign_callback = # ... implementation ...

        statement_uri = await dispatch_register_to_chain(stmt_entry, creator_uri, author_account, authorization_uri, sign_callback)
        print('Statement registered with URI:', statement_uri)
    """
    try:
        api = ConfigService.get('api')
        extrinsic = await prepare_extrinsic_to_register(
            stmt_entry,
            creator_uri,
            author_account,
            authorization_uri,
            sign_callback
        )

        extrinsic = api.create_signed_extrinsic(extrinsic, author_account)
        api.submit_extrinsic(extrinsic,wait_for_inclusion=True)

        return stmt_entry['element_uri']
    except Exception as error:
        raise Exception(f'Error dispatching to chain: "{error}".')


async def dispatch_update_to_chain(
    stmt_entry, creator_uri, author_account, authorization_uri, sign_callback
):
    """
    Dispatches a statement update transaction to the CORD blockchain.

    This function is used to update an existing statement on the blockchain.
    It first checks if the statement with the given digest and space URI already exists.
    If it does, the function constructs and submits a transaction to update the statement.
    The transaction is authorized by the creator and signed by the provided author account.

    Args:
        stmt_entry (dict): The statement entry object containing the necessary information
            for updating the statement on the blockchain. This includes the digest, element URI,
            creator URI, space URI, and optionally a schema URI.
        creator_uri (str): The DID URI of the creator of the statement. This identifier is
            used to authorize the transaction.
        author_account (object): The blockchain account used to sign and submit the transaction.
        authorization_uri (str): The URI of the authorization used for the statement.
        sign_callback (function): A callback function that handles the signing of the transaction.

    Returns:
        str: The element URI of the updated statement.

    Raises:
        CordDispatchError: Thrown when there is an error during the dispatch process,
            such as issues with constructing the transaction, signing, or submission to the blockchain.

    Example:
        stmt_entry = {
            # ... initialization of statement properties ...
        }
        creator_uri = 'did:cord:creator_uri'
        author_account = # ... initialization ...
        authorization_uri = 'auth:cord:example_uri'
        sign_callback = # ... implementation ...

        dispatch_update_to_chain(stmt_entry, creator_uri, author_account, authorization_uri, sign_callback)
        .then(statement_uri => {
            print('Statement updated with URI:', statement_uri)
        })
        .catch(error => {
            print('Error dispatching statement update to chain:', error)
        })
    """
    try:
        api = ConfigService.get('api')
        authorization_id = uri_to_identifier(authorization_uri)
        exists = await is_statement_stored(stmt_entry['digest'], stmt_entry['space_uri'])

        if exists:
            return stmt_entry['element_uri']

        stmt_id_digest = uri_to_statement_id_and_digest(stmt_entry['element_uri'])
        
        tx = api.compose_call(
            call_module='Statement',
            call_function='update',
            call_params={
                'statement_id': stmt_id_digest['identifier'],
                'new_statement_digest': stmt_entry['digest'],
                'authorization': authorization_id
            }
        )

        extrinsic = await Did.authorize_tx(
            creator_uri,
            tx,
            sign_callback,
            author_account.ss58_address
        )

        extrinsic = api.create_signed_extrinsic(extrinsic, author_account)
        api.submit_extrinsic(extrinsic, wait_for_inclusion=True)

        return stmt_entry['element_uri']
    except Exception as error:
        raise Errors.CordDispatchError(f'Error dispatching to chain: "{error}".')


def decode_statement_details_from_chain(encoded, identifier):
    """
    Decodes statement details from their blockchain-encoded format.

    This function is utilized to transform blockchain-specific encoded data of a statement into a more accessible format,
    conforming to the IStatementDetails interface. It decodes the statement's details, including its digest, space URI, and schema URI.

    Args:
        encoded (Option[PalletStatementStatementDetails]): The encoded data of the statement, retrieved directly from the blockchain.
        identifier (str): The identifier of the statement, used to construct its URI.

    Returns:
        dict: An IStatementDetails object containing the decoded details of the statement.

    Example:
        encoded_data = # ... blockchain response ...
        statement_identifier = 'example_identifier'
        statement_details = decode_statement_details_from_chain(encoded_data, statement_identifier)
        print('Decoded Statement Details:', statement_details)
    """
    chain_statement = encoded.value
    schema_details = (chain_statement['schema']) or None

    schema_uri = identifier_to_uri(schema_details) if schema_details is not None else None

    statement = {
        'uri': identifier_to_uri(identifier),
        'digest': chain_statement['digest'],
        'space_uri': identifier_to_uri(chain_statement['space']),
        'schema_uri': schema_uri
    }
    return statement

async def get_details_from_chain(identifier):
    """
    Retrieves detailed state information of a statement from the CORD blockchain.

    This internal function fetches and decodes the details of a statement, identified by its unique identifier, from the blockchain.
    It returns the detailed information of the statement, including its digest, space URI, and schema URI.

    Args:
        identifier (str): The unique identifier of the statement whose details are being fetched.

    Returns:
        dict | None: An IStatementDetails object containing detailed information about the statement,
        or None if the statement is not found.

    Raises:
        StatementError: Thrown when no statement with the provided identifier is found on the blockchain.

    Example:
        statement_id = 'example_identifier'
        statement_details = await get_details_from_chain(statement_id)
        print('Statement Details:', statement_details)
    """
    api = ConfigService.get('api')
    statement_id = uri_to_identifier(identifier)

    statement_entry = api.query("Statement", "Statements", [statement_id])
    decoded_details = decode_statement_details_from_chain(statement_entry, identifier)
    if decoded_details is None:
        raise Errors.StatementError(f'There is no statement with the provided ID "{statement_id}" present on the chain.')

    return decoded_details


async def fetch_statement_details_from_chain(stmt_uri):
    """
    Fetches the state of a statement element from the CORD blockchain.

    This function queries the blockchain to retrieve the current state of a statement,
    identified by its URI. It returns comprehensive details about the statement, including its
    digest, space URI, creator URI, schema URI (if applicable), and revocation status.

    Args:
        stmt_uri (str): The URI of the statement whose status is being fetched.

    Returns:
        dict | None: An IStatementStatus object containing the statement's details,
        or None if the statement is not found.

    Raises:
        StatementError: Thrown when the statement or its entry is not found on the blockchain.

    Example:
        statement_uri = 'stmt:cord:example_uri'
        statement_status = await fetch_statement_details_from_chain(statement_uri)
        print('Statement Status:', statement_status)
    """
    api = ConfigService.get('api')
    res = uri_to_statement_id_and_digest(stmt_uri)
    identifier = res['identifier']
    digest = res['digest']
    statement_details = await get_details_from_chain(identifier)
    if statement_details is None:
        raise Errors.StatementError(f'There is no statement with the provided ID "{identifier}" present on the chain.')

    schema_uri = identifier_to_uri(statement_details['schema_uri']) if statement_details['schema_uri'] is not None else None
    space_uri = identifier_to_uri(statement_details['space_uri'])

    element_status_details = api.query("Statement", "Entries", [identifier, digest])

    if element_status_details is None:
        raise Errors.StatementError(f'There is no entry with the provided ID "{identifier}" and digest "{digest}" present on the chain.')

    element_chain_creator = element_status_details.value
    element_creator = Did.from_chain(element_chain_creator)
    element_status = api.query("Statement", "RevocationList", [identifier, digest])
    revoked = False
    if element_status.value is not None:
        encoded_status = element_status.value
        revoked = encoded_status['revoked']

    statement_status = {
        'uri': statement_details['uri'],
        'digest': digest,
        'space_uri': space_uri,
        'creator_uri': element_creator,
        'schema_uri': schema_uri,
        'revoked': revoked,
    }

    return statement_status

async def prepare_extrinsic_to_revoke(statement_uri, creator_uri, author_account, authorization_uri, sign_callback):
    """
    Dispatches a statement revocation transaction to the CORD blockchain.

    This function is responsible for revoking an existing statement on the blockchain.
    It constructs and submits a transaction to revoke the statement identified by the given URI.
    The transaction is authorized by the creator and signed by the provided author account.

    Args:
        statement_uri (str): The URI of the statement to be revoked.
        creator_uri (str): The DID URI of the creator of the statement. This identifier is used to authorize the transaction.
        author_account (CordKeyringPair): The blockchain account used to sign and submit the transaction.
        authorization_uri (str): The URI of the authorization used for the statement.
        sign_callback (function): A callback function that handles the signing of the transaction.

    Returns:
        SubmittableExtrinsic: A promise that resolves once the transaction is successfully processed.

    Raises:
        SDKErrors.CordDispatchError: Thrown when there is an error during the dispatch process, such as issues with
                                     constructing the transaction, signing, or submission to the blockchain.

    Example:
        statement_uri = 'stmt:cord:example_uri'
        creator_uri = 'did:cord:creator_uri'
        author_account = # ... initialization ...
        authorization_uri = 'auth:cord:example_uri'
        sign_callback = # ... implementation ...

        extrinsic = await prepare_extrinsic_to_revoke(statement_uri, creator_uri, author_account, authorization_uri, sign_callback)
        print('Extrinsic prepared:', extrinsic)
    """
    try:
        api = ConfigService.get('api')
        authorization_id = uri_to_identifier(authorization_uri)

        stmt_id_digest = uri_to_statement_id_and_digest(statement_uri)
        stmt_id = stmt_id_digest['identifier']

        tx = api.compose_call(
            call_module='Statement',
            call_function='revoke',
            call_params={
                'statement_id': stmt_id,
                'authorization': authorization_id
            }
        )

        extrinsic = await Did.authorize_tx(
            creator_uri,
            tx,
            sign_callback,
            author_account.ss58_address
        )

        return extrinsic
    except Exception as error:
        raise Errors.CordDispatchError(f'Error returning extrinsic:: "{error}".')

async def dispatch_revoke_to_chain(statement_uri, creator_uri, author_account, authorization_uri, sign_callback):
    """
    Dispatches a revocation transaction to a blockchain network after preparing
    the necessary extrinsic data.

    Args:
        statement_uri (str): The URI of the statement that you want to revoke on the chain.
        creator_uri (str): The URI that identifies the creator of the statement being revoked.
        author_account (dict): A dictionary representing the account of the author who is revoking the statement.
                               This dictionary typically contains the public key, private key, and other account
                               information needed to sign and submit transactions.
        authorization_uri (str): A Uniform Resource Identifier (URI) that specifies the location or identifier
                                 of the authorization being revoked.
        sign_callback (function): A callback function that is used to sign the extrinsic before submitting it to
                                  the chain. This callback function typically takes care of signing the transaction
                                  using the private key of the account associated with the author of the statement.

    Raises:
        CordDispatchError: Thrown when there is an error during the dispatch process, such as issues with
                           constructing the transaction, signing, or submission to the blockchain.

    Example:
        statement_uri = 'stmt:cord:example_uri'
        creator_uri = 'did:cord:creator_uri'
        author_account = {'address': 'example_address', 'public_key': 'public_key', 'private_key': 'private_key'}
        authorization_uri = 'auth:cord:example_uri'
        sign_callback = lambda tx: tx  # Replace with actual sign callback

        asyncio.run(dispatch_revoke_to_chain(statement_uri, creator_uri, author_account, authorization_uri, sign_callback))
    """
    try:
        api = ConfigService.get('api')
        tx = await prepare_extrinsic_to_revoke(
            statement_uri,
            creator_uri,
            author_account,
            authorization_uri,
            sign_callback
        )
        extrinsic = api.create_signed_extrinsic(tx, author_account)
        api.submit_extrinsic(extrinsic, wait_for_inclusion=True)
    except Exception as error:
        raise Errors.CordDispatchError(f'Error dispatching to chain: "{error}".')


async def dispatch_restore_to_chain(statement_uri, creator_uri, author_account, authorization_uri, sign_callback):
    """
    Dispatches a statement restoration transaction to the CORD blockchain.

    This function is responsible for restoring a previously revoked statement on the blockchain.
    It constructs and submits a transaction to restore the statement identified by the given URI.
    The transaction is authorized by the creator and signed by the provided author account.

    Args:
        statement_uri (str): The URI of the statement to be restored.
        creator_uri (str): The DID URI of the creator of the statement. This identifier is used to authorize the transaction.
        author_account (dict): A dictionary representing the account of the author who is restoring the statement.
                               This dictionary typically contains the public key, private key, and other account information
                               needed to sign and submit transactions.
        authorization_uri (str): The URI of the authorization used for the statement.
        sign_callback (function): A callback function that handles the signing of the transaction.

    Raises:
        CordDispatchError: Thrown when there is an error during the dispatch process, such as issues with constructing
                           the transaction, signing, or submission to the blockchain.

    Example:
        statement_uri = 'stmt:cord:example_uri'
        creator_uri = 'did:cord:creator_uri'
        author_account = {'address': 'example_address', 'public_key': 'public_key', 'private_key': 'private_key'}
        authorization_uri = 'auth:cord:example_uri'
        sign_callback = lambda tx: tx  # Replace with actual sign callback

        asyncio.run(dispatch_restore_to_chain(statement_uri, creator_uri, author_account, authorization_uri, sign_callback))
    """
    try:
        api = ConfigService.get('api')
        authorization_id = uri_to_identifier(authorization_uri)

        stmt_id_digest = uri_to_statement_id_and_digest(statement_uri)
        stmt_id = stmt_id_digest['identifier']

        tx = api.compose_call(
            call_module='Statement',
            call_function='restore',
            call_params={
                'statement_id': stmt_id,
                'authorization': authorization_id
            }
        )

        extrinsic = await Did.authorize_tx(
            creator_uri,
            tx,
            sign_callback,
            author_account.ss58_address
        )
        extrinsic = api.create_signed_extrinsic(extrinsic, author_account)
        api.submit_extrinsic(extrinsic, wait_for_inclusion=True)
    except Exception as error:
        raise Errors.CordDispatchError(f'Error dispatching to chain: "{error}".')