import unittest
from unittest.mock import patch, MagicMock, AsyncMock
import packages.sdk.src as Cord
import asyncio
from packages.identifier.src.identifier import (
    hash_to_uri,
    uri_to_identifier,
    identifier_to_uri
)

# Global test constants
TEST_SCHEMA = {
    "$id": "schema:cord:s36R1RNXcAytTPd3fsVMVbhCvVQ5B6fi8r722euvBMMdUeXSH",
    "$metadata": {"discoverable": True, "slug": "test-demo-schema", "version": "1.0.0"},
    "$schema": "http://cord.network/draft-01/schema#",
    "additionalProperties": False,
    "description": "Test Demo Schema",
    "properties": {
        "address": {
            "properties": {
                "location": {
                    "properties": {
                        "country": {"type": "string"},
                        "state": {"type": "string"},
                    },
                    "type": "object",
                },
                "pin": {"type": "integer"},
                "street": {"type": "string"},
            },
            "type": "object",
        },
        "age": {"type": "integer"},
        "country": {"type": "string"},
        "id": {"type": "string"},
        "name": {"type": "string"},
    },
    "title": "Test Demo Schema v3:d2916ae8-0f07-451a-a378-c1beaa5984c1",
    "type": "object",
}

TEST_CREATOR_URI = "did:cord:3yrn8NahRARGPodzjQQobkhujkYZbzsWttk5QoSEL7qLMfCu"
TEST_SPACE_URI = "space:cord:c37c6MvhrZLXs9AfnsLYxApfjtc1y9s3fACvrD95NYoWD2UE8"
TEST_AUTHOR_ACCOUNT = MagicMock()
TEST_AUTHORIZATION_URI = "auth:cord:a3fraTJoz9yDKpvMyAJJ971F3p7Ts1bfBz2WyMojvYqQNjf6S"
TEST_STATEMENT_URI = "stmt:cord:s3hHaTwx9G4LXprYLSZVanFWikyyiF4w9NVpoQJZw6AYiMLzw:0981d00f89ae59be7a3d97b1c0b35fdbabbe55211400a9a2c029aa00701048eb"
TEST_SCHEMA_URI = "schema:cord:s36R1RNXcAytTPd3fsVMVbhCvVQ5B6fi8r722euvBMMdUeXSH"
TEST_SIGNATURE_CALLBACK = MagicMock()


class TestCordSchemaFunctions(unittest.TestCase):
    module_path = "packages.sdk.src.Schema.schema_chain"

    @patch(f'{module_path}.encode_cbor_schema')
    @patch(f'{module_path}.Utils.crypto_utils.hash_str')
    @patch(f'{module_path}.Utils.crypto_utils.blake2_as_hex')
    @patch(f'{module_path}.hash_to_uri')
    @patch(f"{module_path}.ConfigService.get")
    def test_get_uri_for_schema(self, mock_get, mock_hash_to_uri, mock_blake2_as_hex, mock_hash_str, mock_encode_cbor_schema):
        # Mock API and other utility functions
        mock_api = MagicMock()
        mock_get.return_value = mock_api
        mock_encode_cbor_schema.return_value = "encoded_cbor_schema"
        mock_hash_str.return_value = "test_digest"
        mock_blake2_as_hex.return_value = "test_blake2_hash"
        mock_hash_to_uri.return_value = TEST_SCHEMA_URI

        # Mock encoding functions
        mock_api.encode_scale.side_effect = [
            MagicMock(get_remaining_bytes=MagicMock(return_value=b'serialized_schema_bytes')),
            MagicMock(get_remaining_bytes=MagicMock(return_value=b'space_bytes')),
            MagicMock(get_remaining_bytes=MagicMock(return_value=b'creator_bytes'))
        ]

        # Call the function
        result = Cord.Schema.schema_chain.get_uri_for_schema(TEST_SCHEMA, TEST_CREATOR_URI, TEST_SPACE_URI)

        # Assertions
        self.assertEqual(result['uri'], TEST_SCHEMA_URI)
        self.assertEqual(result['digest'], "test_digest")

        # Ensure encoding and hashing was done correctly
        mock_encode_cbor_schema.assert_called_once_with(TEST_SCHEMA)
        mock_hash_str.assert_called_once_with(b"encoded_cbor_schema")
        mock_api.encode_scale.assert_any_call(type_string="Bytes", value="encoded_cbor_schema")
        mock_api.encode_scale.assert_any_call(type_string="Bytes", value=uri_to_identifier(TEST_SPACE_URI))
        mock_api.encode_scale.assert_any_call(type_string="AccountId", value=Cord.Did.to_chain(TEST_CREATOR_URI))
        mock_blake2_as_hex.assert_called_once_with(b'serialized_schema_bytes' + b'space_bytes' + b'creator_bytes')


    @patch(f"{module_path}.ConfigService.get")
    @patch(f"{module_path}.uri_to_identifier")
    def test_is_schema_stored(self, mock_uri_to_identifier, mock_get):
        mock_api = MagicMock()
        mock_get.return_value = mock_api

        mock_api.query.return_value.value = None
        schema_exists = asyncio.run(
            Cord.Schema.schema_chain.is_schema_stored(TEST_SCHEMA)
        )
        self.assertFalse(schema_exists)

        mock_api.query.return_value.value = True
        schema_exists = asyncio.run(
            Cord.Schema.schema_chain.is_schema_stored(TEST_SCHEMA)
        )
        self.assertTrue(schema_exists)

    @patch(f"{module_path}.ConfigService.get")
    @patch(f"{module_path}.is_schema_stored", new_callable=AsyncMock)
    @patch(f"{module_path}.Did.authorize_tx", new_callable=AsyncMock)
    def test_dispatch_to_chain_success(
        self, mock_authorize_tx, mock_is_schema_stored, mock_get
    ):
        # Success test for schema dispatching to chain
        mock_api = MagicMock()
        mock_get.return_value = mock_api
        mock_is_schema_stored.return_value = False  # Schema is not already stored
        mock_authorize_tx.return_value = "signed_tx"

        # Mock API methods
        mock_api.create_signed_extrinsic.return_value = "signed_extrinsic"
        mock_api.submit_extrinsic.return_value = None

        # Run the async function
        result = asyncio.run(
            Cord.Schema.schema_chain.dispatch_to_chain(
                TEST_SCHEMA,
                TEST_CREATOR_URI,
                TEST_AUTHOR_ACCOUNT,
                TEST_AUTHORIZATION_URI,
                TEST_SIGNATURE_CALLBACK,
            )
        )

        # Assert that the schema ID is returned
        self.assertEqual(result, TEST_SCHEMA["$id"])

        # Assert the proper call sequence
        mock_is_schema_stored.assert_awaited_once_with(TEST_SCHEMA)
        mock_authorize_tx.assert_awaited_once_with(
            TEST_CREATOR_URI,
            mock_api.compose_call.return_value,
            TEST_SIGNATURE_CALLBACK,
            TEST_AUTHOR_ACCOUNT.ss58_address,
        )
        mock_api.create_signed_extrinsic.assert_called_once_with(
            call="signed_tx", keypair=TEST_AUTHOR_ACCOUNT
        )
        mock_api.submit_extrinsic.assert_called_once_with(
            "signed_extrinsic", wait_for_inclusion=True
        )

    @patch(f"{module_path}.ConfigService.get")
    @patch(f"{module_path}.is_schema_stored", new_callable=AsyncMock)
    @patch(f"{module_path}.Did.authorize_tx", new_callable=AsyncMock)
    def test_dispatch_to_chain_schema_already_exists(
        self, mock_authorize_tx, mock_is_schema_stored, mock_get
    ):
        # Test when schema already exists in the chain
        mock_api = MagicMock()
        mock_get.return_value = mock_api
        mock_is_schema_stored.return_value = True  # Schema is already stored

        result = asyncio.run(
            Cord.Schema.schema_chain.dispatch_to_chain(
                TEST_SCHEMA,
                TEST_CREATOR_URI,
                TEST_AUTHOR_ACCOUNT,
                TEST_AUTHORIZATION_URI,
                TEST_SIGNATURE_CALLBACK,
            )
        )

        # Assert that the schema ID is returned and no transaction was submitted
        self.assertEqual(result, TEST_SCHEMA["$id"])
        mock_is_schema_stored.assert_awaited_once_with(TEST_SCHEMA)
        mock_authorize_tx.assert_not_called()
        mock_api.create_signed_extrinsic.assert_not_called()
        mock_api.submit_extrinsic.assert_not_called()

    @patch(f"{module_path}.ConfigService.get")
    @patch(f"{module_path}.from_chain")
    def test_fetch_from_chain(self, mock_from_chain, mock_get):
        mock_api = MagicMock()
        mock_get.return_value = mock_api

        mock_from_chain.return_value = {"schema": TEST_SCHEMA}
        mock_api.query.return_value = MagicMock(value="some_value")

        result = asyncio.run(
            Cord.Schema.schema_chain.fetch_from_chain(TEST_SCHEMA_URI)
        )

        self.assertIn("schema", result)
        self.assertEqual(result["schema"], TEST_SCHEMA)

    @patch(f"{module_path}.cbor2.loads")
    def test_schema_input_from_chain(self, mock_loads):
        mock_loads.return_value = TEST_SCHEMA
        input_data = "base64_encoded_input=="

        result = Cord.Schema.schema_chain.schema_input_from_chain(
            input_data, TEST_SCHEMA_URI
        )
        self.assertIn("$id", result)
        self.assertEqual(result["$id"], TEST_SCHEMA_URI)


if __name__ == "__main__":
    unittest.main()
