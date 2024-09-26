import unittest
from unittest.mock import MagicMock, patch
import asyncio
from packages.utils.src.SDKErrors import Errors
from packages.utils.src.prefix import ASSET_PREFIX
import packages.sdk.src as Cord

# Global test constants
TEST_ASSET_ENTRY = {
    "creator": "did:cord:creator",
    "issuer": "did:cord:issuer",
    "owner": "did:cord:owner",
    "entry": {"asset_id": "123", "asset_instance_id": "456"},
    "digest": "dummy_digest",
    "uri": "asset:cord:123:456"
}
TEST_AUTHOR_ACCOUNT = MagicMock()
TEST_AUTHORIZATION_URI = "auth:cord:a3fraTJoz9yDKpvMyAJJ971F3p7Ts1bfBz2WyMojvYqQNjf6S"
TEST_SIGNATURE_CALLBACK = MagicMock()

class TestCordAssetFunctions(unittest.TestCase):

    @patch('packages.sdk.src.ConfigService.get')
    @patch('packages.sdk.src.Did.authorize_tx')
    def test_dispatch_create_to_chain_success(self, mock_authorize_tx, mock_get):
        mock_api = MagicMock()
        mock_get.return_value = mock_api
        mock_authorize_tx.return_value = "signed_tx"

        mock_api.compose_call.return_value = "tx_call"
        mock_api.create_signed_extrinsic.return_value = "signed_extrinsic"
        mock_api.submit_extrinsic.return_value = None

        result = asyncio.run(
            Cord.Asset.asset_chain.dispatch_create_to_chain(
                TEST_ASSET_ENTRY,
                TEST_AUTHOR_ACCOUNT,
                TEST_AUTHORIZATION_URI,
                TEST_SIGNATURE_CALLBACK
            )
        )

        self.assertEqual(result, TEST_ASSET_ENTRY["uri"])

    @patch('packages.sdk.src.ConfigService.get')
    @patch('packages.sdk.src.Did.authorize_tx')
    def test_dispatch_create_to_chain_failure(self, mock_authorize_tx, mock_get):
        mock_get.return_value = MagicMock()
        mock_authorize_tx.side_effect = Exception("Authorization failed")

        with self.assertRaises(Errors.CordDispatchError):
            asyncio.run(
                Cord.Asset.asset_chain.dispatch_create_to_chain(
                    TEST_ASSET_ENTRY,
                    TEST_AUTHOR_ACCOUNT,
                    TEST_AUTHORIZATION_URI,
                    TEST_SIGNATURE_CALLBACK
                )
            )

    @patch('packages.sdk.src.ConfigService.get')
    @patch('packages.sdk.src.Did.authorize_tx')
    def test_dispatch_issue_to_chain_success(self, mock_authorize_tx, mock_get):
        mock_api = MagicMock()
        mock_get.return_value = mock_api
        mock_authorize_tx.return_value = "signed_tx"

        mock_api.create_signed_extrinsic.return_value = "signed_extrinsic"
        mock_api.submit_extrinsic.return_value = None

        result = asyncio.run(
            Cord.Asset.asset_chain.dispatch_issue_to_chain(
                TEST_ASSET_ENTRY,
                TEST_AUTHOR_ACCOUNT,
                TEST_AUTHORIZATION_URI,
                TEST_SIGNATURE_CALLBACK
            )
        )

        self.assertEqual(result, TEST_ASSET_ENTRY["uri"])

    @patch('packages.sdk.src.ConfigService.get')
    @patch('packages.sdk.src.Did.authorize_tx')
    def test_dispatch_issue_to_chain_failure(self, mock_authorize_tx, mock_get):
        mock_get.return_value = MagicMock()
        mock_authorize_tx.side_effect = Exception("Authorization failed")

        with self.assertRaises(Errors.CordDispatchError):
            asyncio.run(
                Cord.Asset.asset_chain.dispatch_issue_to_chain(
                    TEST_ASSET_ENTRY,
                    TEST_AUTHOR_ACCOUNT,
                    TEST_AUTHORIZATION_URI,
                    TEST_SIGNATURE_CALLBACK
                )
            )

    @patch('packages.sdk.src.ConfigService.get')
    @patch('packages.sdk.src.Did.authorize_tx')
    def test_dispatch_transfer_to_chain_success(self, mock_authorize_tx, mock_get):
        mock_api = MagicMock()
        mock_get.return_value = mock_api
        mock_authorize_tx.return_value = "signed_tx"

        mock_api.create_signed_extrinsic.return_value = "signed_extrinsic"
        mock_api.submit_extrinsic.return_value = None

        result = asyncio.run(
            Cord.Asset.asset_chain.dispatch_transfer_to_chain(
                TEST_ASSET_ENTRY,
                TEST_AUTHOR_ACCOUNT,
                TEST_SIGNATURE_CALLBACK
            )
        )

        self.assertEqual(result, f"{ASSET_PREFIX}{TEST_ASSET_ENTRY['entry']['asset_id']}:{TEST_ASSET_ENTRY['entry']['asset_instance_id']}")

    @patch('packages.sdk.src.ConfigService.get')
    @patch('packages.sdk.src.Did.authorize_tx')
    def test_dispatch_transfer_to_chain_failure(self, mock_authorize_tx, mock_get):
        mock_get.return_value = MagicMock()
        mock_authorize_tx.side_effect = Exception("Authorization failed")

        with self.assertRaises(Errors.CordDispatchError):
            asyncio.run(
                Cord.Asset.asset_chain.dispatch_transfer_to_chain(
                    TEST_ASSET_ENTRY,
                    TEST_AUTHOR_ACCOUNT,
                    TEST_SIGNATURE_CALLBACK
                )
            )

if __name__ == '__main__':
    unittest.main()
