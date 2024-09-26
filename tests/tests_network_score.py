import unittest
from unittest.mock import AsyncMock, patch, MagicMock
from packages.utils.src.SDKErrors import Errors
import packages.sdk.src as Cord
import asyncio

# Mock test constants
TEST_RATING_URI = "rating:cord:r35hzaE3KFVDuZB24bEkeWu38rXK5SavZNe8xomJjp7ZCsvFf"
TEST_AUTHORIZATION_URI = "auth:cord:a3fraTJoz9yDKpvMyAJJ971F3p7Ts1bfBz2WyMojvYqQNjf6S"
TEST_AUTHOR_ACCOUNT = MagicMock(ss58_address="5F3sa2TJ...")
TEST_SIGN_CALLBACK = MagicMock()
TEST_RATING_ENTRY = {
    "entry": {
        "reference_id": "rating:cord:r37i2uLYsxfj7vkAFaFzhMkT16ns11EELkWY7zJ6ErF8z5Ewf",
        "entry_digest": "some_digest",
    },
    "entry_digest": "0x5015dd7c7baea48731b083baabd799f9d479c96ab0aa65a199cf92e2cca5eeb3",
    "message_id": "msg123",
    "entry_uri": TEST_RATING_URI,
    "author_uri": "did:cord:author:0001",
}
ENCODED_RATING = {
    "entry": {
        "entity_id": "entity123",
        "provider_id": "provider123",
        "rating_type": "overall",
        "count_of_txn": 10,
        "total_encoded_rating": 850,
        
    },
    "digest": "digest123",
    "message_id": "msg123",
    "space": "space123",
    "reference_id": "rating:cord:r37i2uLYsxfj7vkAFaFzhMkT16ns11EELkWY7zJ6ErF8z5Ewf",
    "creator_id": "creator123",
    "entry_type": "type123",
    "created_at": 1694074734000,
}


class TestRatingModule(unittest.TestCase):

    @patch("packages.sdk.src.ConfigService.get")
    @patch("packages.identifier.src.identifier.uri_to_identifier")
    def test_is_rating_stored_true(self, mock_uri_to_identifier, mock_config_service):
        """
        Test is_rating_stored function when rating is stored.
        """
        mock_api = MagicMock()
        mock_api.query.return_value.value = ENCODED_RATING
        mock_config_service.return_value = mock_api
        mock_uri_to_identifier.return_value = "rating_identifier"

        result = asyncio.run(Cord.Score.scoring_chain.is_rating_stored(TEST_RATING_URI))
        self.assertTrue(result)
        mock_api.query.assert_called_with(
            "NetworkScore", "RatingEntries", ["r35hzaE3KFVDuZB24bEkeWu38rXK5SavZNe8xomJjp7ZCsvFf"]
        )

    @patch("packages.sdk.src.ConfigService.get")
    @patch("packages.identifier.src.identifier.uri_to_identifier")
    def test_is_rating_stored_false(self, mock_uri_to_identifier, mock_config_service):
        """
        Test is_rating_stored function when rating is not stored.
        """
        mock_api = MagicMock()
        mock_api.query.return_value.value = None
        mock_config_service.return_value = mock_api
        mock_uri_to_identifier.return_value = "rating_identifier"

        result = asyncio.run(Cord.Score.scoring_chain.is_rating_stored(TEST_RATING_URI))
        self.assertFalse(result)

    @patch("packages.sdk.src.ConfigService.get")
    def test_dispatch_rating_to_chain_success(self, mock_config_service):
        """
        Test dispatch_rating_to_chain function for successful dispatch.
        """
        mock_api = MagicMock()
        mock_api.query.return_value.value = None  # Rating does not exist
        mock_api.compose_call.return_value = "mock_call"
        mock_api.create_signed_extrinsic.return_value = "mock_extrinsic"
        mock_config_service.return_value = mock_api

        with patch(
            "packages.sdk.src.Did.authorize_tx",
            new=AsyncMock(return_value="authorized_tx"),
        ):
            result = asyncio.run(
                Cord.Score.scoring_chain.dispatch_rating_to_chain(
                    TEST_RATING_ENTRY,
                    TEST_AUTHOR_ACCOUNT,
                    TEST_AUTHORIZATION_URI,
                    TEST_SIGN_CALLBACK,
                )
            )
            self.assertEqual(result, TEST_RATING_ENTRY["entry_uri"])
            mock_api.compose_call.assert_called_once()
            mock_api.submit_extrinsic.assert_called_once_with(
                "mock_extrinsic", wait_for_inclusion=True
            )

    @patch("packages.sdk.src.ConfigService.get")
    def test_dispatch_rating_to_chain_already_exists(self, mock_config_service):
        """
        Test dispatch_rating_to_chain function when rating already exists.
        """
        mock_api = MagicMock()
        mock_api.query.return_value.value = ENCODED_RATING  # Rating exists
        mock_config_service.return_value = mock_api

        result = asyncio.run(
            Cord.Score.scoring_chain.dispatch_rating_to_chain(
                TEST_RATING_ENTRY,
                TEST_AUTHOR_ACCOUNT,
                TEST_AUTHORIZATION_URI,
                TEST_SIGN_CALLBACK,
            )
        )
        self.assertEqual(result, TEST_RATING_ENTRY["entry_uri"])
        mock_api.compose_call.assert_not_called()  # Should not attempt to create a transaction

    @patch("packages.sdk.src.ConfigService.get")
    def test_dispatch_revoke_rating_to_chain_success(self, mock_config_service):
        """
        Test dispatch_revoke_rating_to_chain for successful revocation.
        """
        mock_api = MagicMock()
        mock_api.query.return_value.value = ENCODED_RATING  # Rating exists
        mock_api.compose_call.return_value = "mock_call"
        mock_api.create_signed_extrinsic.return_value = "mock_extrinsic"
        mock_config_service.return_value = mock_api

        with patch(
            "packages.sdk.src.Did.authorize_tx",
            new=AsyncMock(return_value="authorized_tx"),
        ):
            result = asyncio.run(Cord.Score.scoring_chain.dispatch_revoke_rating_to_chain(
                TEST_RATING_ENTRY,
                TEST_AUTHOR_ACCOUNT,
                TEST_AUTHORIZATION_URI,
                TEST_SIGN_CALLBACK,
            ))
            self.assertEqual(result, TEST_RATING_ENTRY["entry_uri"])
            mock_api.submit_extrinsic.assert_called_once_with(
                "mock_extrinsic", wait_for_inclusion=True
            )

    @patch("packages.sdk.src.ConfigService.get")
    def test_dispatch_revoke_rating_to_chain_not_found(self, mock_config_service):
        """
        Test dispatch_revoke_rating_to_chain when rating entry is not found.
        """
        mock_api = MagicMock()
        mock_api.query.return_value.value = None  # Rating does not exist
        mock_config_service.return_value = mock_api

        with self.assertRaises(Errors.CordDispatchError):
            asyncio.run(Cord.Score.scoring_chain.dispatch_revoke_rating_to_chain(
                TEST_RATING_ENTRY,
                TEST_AUTHOR_ACCOUNT,
                TEST_AUTHORIZATION_URI,
                TEST_SIGN_CALLBACK,
            ))
    
    @patch("packages.sdk.src.ConfigService.get")
    def test_fetch_rating_details_from_chain_not_found(self, mock_config_service):
        """
        Test fetch_rating_details_from_chain when the rating entry is not found.
        """
        mock_api = MagicMock()
        mock_api.query.return_value.value = None
        mock_config_service.return_value = mock_api

        result = asyncio.run(Cord.Score.scoring_chain.fetch_rating_details_from_chain(TEST_RATING_URI, "GMT"))
        self.assertIsNone(result)

    @patch("packages.sdk.src.ConfigService.get")
    def test_fetch_entity_aggregate_score_from_chain_found(
        self, mock_config_service
    ):
        """
        Test fetch_entity_aggregate_score_from_chain when data is found.
        """
        mock_api = MagicMock()
        mock_api.query.return_value.value = {
            "count_of_txn": 100,
            "total_encoded_rating": 950,
        }
        mock_config_service.return_value = mock_api

        result = asyncio.run(Cord.Score.scoring_chain.fetch_entity_aggregate_score_from_chain("entity123", "overall"))
        self.assertIsNotNone(result)
        self.assertEqual(result[0]["count_of_txn"], 100)
        self.assertEqual(result[0]["total_rating"], 95.0)

    @patch("packages.sdk.src.ConfigService.get")
    def test_fetch_entity_aggregate_score_from_chain_not_found(
        self, mock_config_service
    ):
        """
        Test fetch_entity_aggregate_score_from_chain when no data is found.
        """
        mock_api = MagicMock()
        mock_api.query.return_value.value = None
        mock_config_service.return_value = mock_api

        result = asyncio.run(Cord.Score.scoring_chain.fetch_entity_aggregate_score_from_chain("entity123", "overall"))
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
