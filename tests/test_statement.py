import unittest
from unittest.mock import patch, MagicMock, AsyncMock
from packages.utils.src.SDKErrors import Errors
import asyncio
import packages.sdk.src as Cord

# Global Constants
DIGEST = '0x98b7e7117df3e7b12f31cc9ea97e10f83c807ffa082cb4950c0c3cae5bbb6e3e'
SPACE_URI = 'space:cord:c33wBzcYTn22DPqLbeeJ5U3DEcLSywwNzVvp7iRXP2P6WPu5W'
CREATOR_URI = 'did:cord:3uNfAtHEjabBsKVjmxGcAUF4S5cu7VMogXReho3ncPtrL4NV'
ELEMENT_URI = 'stmt:cord:s3do5hWstnvuwbuPcwuCt9bVecLWVc5foyb1LVAU5Sn97ZMLt:98b7e7117df3e7b12f31cc9ea97e10f83c807ffa082cb4950c0c3cae5bbb6e3e'
AUTHORIZATION_URI = 'auth:cord:a3azw9RwhR9xgURZKJM9xSsDDFRUqgUurvdnQXT1UzCPtZQJ8'
SCHEMA_URI = 'schema:cord:s319FZJkZevpitKNdfvxfs7SeiXzuHyX3ncrTo5LDWxZi7qqP'
STMT_ENTRY = {
    'digest': DIGEST,
    'space_uri': SPACE_URI,
    'element_uri': ELEMENT_URI,
    'schema_uri': SCHEMA_URI,
}
STMT_URI = 'stmt:cord:s3do5hWstnvuwbuPcwuCt9bVecLWVc5foyb1LVAU5Sn97ZMLt:98b7e7117df3e7b12f31cc9ea97e10f83c807ffa082cb4950c0c3cae5bbb6e3e'

AUTHOR_ACCOUNT = MagicMock()  # You can configure this further as needed
SIGN_CALLBACK = MagicMock()  # Mock sign callback

class TestStatementFunctions(unittest.TestCase):

    module_path = "packages.sdk.src.Statement.statement_chain"

    @patch('packages.sdk.src.ConfigService.get')
    def test_get_uri_for_statement_failure(self, mock_config):
        """Test get_uri_for_statement failure scenario."""
        mock_api = MagicMock()
        mock_config.return_value = mock_api
        mock_api.encode_scale.side_effect = Exception('Encoding error')

        with self.assertRaises(Exception) as context:
            Cord.Statement.statement_chain.get_uri_for_statement(DIGEST, SPACE_URI, CREATOR_URI)

        self.assertIn('Encoding error', str(context.exception))

    @patch('packages.sdk.src.ConfigService.get')
    @patch(f'{module_path}.uri_to_identifier', return_value='mocked_identifier')
    def test_is_statement_stored_success(self, mock_uri, mock_config):
        """Test is_statement_stored success scenario."""
        mock_api = MagicMock()
        mock_config.return_value = mock_api
        mock_api.query.return_value.value = 'mocked_value'
        
        result = asyncio.run(Cord.Statement.statement_chain.is_statement_stored(DIGEST, SPACE_URI))
        self.assertTrue(result)

    @patch('packages.sdk.src.ConfigService.get')
    @patch(f'{module_path}.uri_to_identifier', return_value='mocked_identifier')
    def test_is_statement_stored_failure(self, mock_uri, mock_config):
        """Test is_statement_stored failure scenario."""
        mock_api = MagicMock()
        mock_config.return_value = mock_api
        mock_api.query.return_value.value = None
        
        result = asyncio.run(Cord.Statement.statement_chain.is_statement_stored(DIGEST, SPACE_URI))
        self.assertFalse(result)

    @patch('packages.sdk.src.ConfigService.get')
    @patch(f'{module_path}.Did.authorize_tx', new_callable=AsyncMock)
    @patch(f'{module_path}.is_statement_stored', return_value=False)
    def test_prepare_extrinsic_to_register_success(self, mock_strored, mock_authorize_tx, mock_config):
        """Test prepare_extrinsic_to_register success scenario."""
        mock_api = MagicMock()
        mock_config.return_value = mock_api
        mock_api.compose_call.return_value = 'mocked_tx'
        mock_authorize_tx.return_value = 'mocked_extrinsic'

        extrinsic = asyncio.run(Cord.Statement.statement_chain.prepare_extrinsic_to_register(
            STMT_ENTRY, CREATOR_URI, AUTHOR_ACCOUNT, AUTHORIZATION_URI, SIGN_CALLBACK
        ))

        self.assertEqual(extrinsic, 'mocked_extrinsic')

    @patch('packages.sdk.src.ConfigService.get')
    @patch(f'{module_path}.Did.authorize_tx', new_callable=AsyncMock)
    @patch(f'{module_path}.is_statement_stored', return_value=False)
    def test_prepare_extrinsic_to_register_failure(self, mock_stored, mock_authorize_tx, mock_config):
        """Test prepare_extrinsic_to_register failure scenario."""
        mock_api = MagicMock()
        mock_config.return_value = mock_api
        mock_api.compose_call.return_value = 'mocked_tx'
        mock_authorize_tx.side_effect = Exception('Authorization failed')

        with self.assertRaises(Errors.CordDispatchError) as context:
            asyncio.run(Cord.Statement.statement_chain.prepare_extrinsic_to_register(
                STMT_ENTRY, CREATOR_URI, AUTHOR_ACCOUNT, AUTHORIZATION_URI, SIGN_CALLBACK
            ))

        self.assertIn('Authorization failed', str(context.exception))

    @patch('packages.sdk.src.ConfigService.get')
    @patch(f'{module_path}.prepare_extrinsic_to_register', new_callable=AsyncMock)
    def test_dispatch_register_to_chain_success(self, mock_prepare_extrinsic, mock_config):
        """Test dispatch_register_to_chain success scenario."""
        mock_api = MagicMock()
        mock_config.return_value = mock_api
        mock_prepare_extrinsic.return_value = 'mocked_extrinsic'
        mock_api.create_signed_extrinsic.return_value = 'signed_extrinsic'

        result = asyncio.run(Cord.Statement.statement_chain.dispatch_register_to_chain(
            STMT_ENTRY, CREATOR_URI, AUTHOR_ACCOUNT, AUTHORIZATION_URI, SIGN_CALLBACK
        ))

        self.assertEqual(result, STMT_ENTRY['element_uri'])

    @patch('packages.sdk.src.ConfigService.get')
    @patch(f'{module_path}.prepare_extrinsic_to_register', new_callable=AsyncMock)
    def test_dispatch_register_to_chain_failure(self, mock_prepare_extrinsic, mock_config):
        """Test dispatch_register_to_chain failure scenario."""
        mock_api = MagicMock()
        mock_config.return_value = mock_api
        mock_prepare_extrinsic.side_effect = Exception('Extrinsic preparation failed')

        with self.assertRaises(Exception) as context:
            asyncio.run(Cord.Statement.statement_chain.dispatch_register_to_chain(
                STMT_ENTRY, CREATOR_URI, AUTHOR_ACCOUNT, AUTHORIZATION_URI, SIGN_CALLBACK
            ))

        self.assertIn('Extrinsic preparation failed', str(context.exception))

    @patch('packages.sdk.src.ConfigService.get')
    @patch(f'{module_path}.is_statement_stored', new_callable=AsyncMock)
    @patch(f'{module_path}.Did.authorize_tx', new_callable=AsyncMock)
    def test_dispatch_update_to_chain_success(self, mock_authorize_tx, mock_is_statement_stored, mock_config):
        """Test dispatch_update_to_chain success scenario."""
        mock_api = MagicMock()
        mock_config.return_value = mock_api
        mock_is_statement_stored.return_value = False
        mock_authorize_tx.return_value = 'mocked_extrinsic'

        result = asyncio.run(Cord.Statement.statement_chain.dispatch_update_to_chain(
            STMT_ENTRY, CREATOR_URI, AUTHOR_ACCOUNT, AUTHORIZATION_URI, SIGN_CALLBACK
        ))

        self.assertEqual(result, STMT_ENTRY['element_uri'])

    @patch('packages.sdk.src.ConfigService.get')
    @patch(f'{module_path}.is_statement_stored', new_callable=AsyncMock)
    @patch(f'{module_path}.Did.authorize_tx', new_callable=AsyncMock)
    def test_dispatch_update_to_chain_failure(self, mock_authorize_tx, mock_is_statement_stored, mock_config):
        """Test dispatch_update_to_chain failure scenario."""
        mock_api = MagicMock()
        mock_config.return_value = mock_api
        mock_is_statement_stored.return_value = False
        mock_authorize_tx.side_effect = Exception('Transaction failed')

        with self.assertRaises(Errors.CordDispatchError) as context:
            asyncio.run(Cord.Statement.statement_chain.dispatch_update_to_chain(
                STMT_ENTRY, CREATOR_URI, AUTHOR_ACCOUNT, AUTHORIZATION_URI, SIGN_CALLBACK
            ))

        self.assertIn('Transaction failed', str(context.exception))

    @patch('packages.sdk.src.ConfigService.get')
    @patch(f'{module_path}.Did.authorize_tx', new_callable=AsyncMock)
    @patch(f'{module_path}.uri_to_identifier', new_callable=MagicMock)
    @patch(f'{module_path}.uri_to_statement_id_and_digest', new_callable=MagicMock)
    def test_prepare_extrinsic_to_revoke_success(self, mock_uri_to_statement_id_and_digest,
                                                 mock_uri_to_identifier, mock_authorize_tx, mock_config):
        """Test prepare_extrinsic_to_revoke success scenario."""
        # Mocking the return values
        mock_api = MagicMock()
        mock_config.return_value = mock_api
        mock_uri_to_identifier.return_value = 'mock_authorization_id'
        mock_uri_to_statement_id_and_digest.return_value = {'identifier': 'mock_statement_id'}
        
        # Mocking the transaction (tx) composed by `api.compose_call`
        mock_api.compose_call.return_value = "mock_composed_tx"
        
        # Mock the authorized transaction
        mock_authorize_tx.return_value = 'authorized_extrinsic'

        # Run the async function using asyncio
        result = asyncio.run(Cord.Statement.statement_chain.prepare_extrinsic_to_revoke(
            STMT_URI, CREATOR_URI, AUTHOR_ACCOUNT, AUTHORIZATION_URI, SIGN_CALLBACK
        ))

        # Asserting the expected results
        self.assertEqual(result, 'authorized_extrinsic')

        # Verifying that the mocks were called with the correct parameters
        mock_config.assert_called_once_with('api')
        mock_uri_to_identifier.assert_called_once_with(AUTHORIZATION_URI)
        mock_uri_to_statement_id_and_digest.assert_called_once_with(ELEMENT_URI)
        mock_api.compose_call.assert_called_once_with(
            call_module='Statement',
            call_function='revoke',
            call_params={
                'statement_id': 'mock_statement_id',
                'authorization': 'mock_authorization_id'
            }
        )
        mock_authorize_tx.assert_called_once_with(
            CREATOR_URI,
            'mock_composed_tx',
            SIGN_CALLBACK,
            AUTHOR_ACCOUNT.ss58_address
        )


    @patch('packages.sdk.src.ConfigService.get')
    @patch(f'{module_path}.prepare_extrinsic_to_revoke', new_callable=AsyncMock)
    @patch(f'{module_path}.Did.authorize_tx', new_callable=AsyncMock)
    def test_dispatch_revoke_to_chain_success(self, mock_authorize_tx, mock_prepare_extrinsic, mock_config):
        """Test dispatch_revoke_to_chain success scenario."""
        mock_api = MagicMock()
        mock_config.return_value = mock_api
        mock_prepare_extrinsic.return_value = 'mocked_extrinsic'
        mock_api.create_signed_extrinsic.return_value = 'signed_extrinsic'
        mock_api.submit_extrinsic.return_value = None  # Assuming submit_extrinsic does not return anything
        
        result = asyncio.run(Cord.Statement.statement_chain.dispatch_revoke_to_chain(
            STMT_URI, CREATOR_URI, AUTHOR_ACCOUNT, AUTHORIZATION_URI, SIGN_CALLBACK
        ))
        self.assertIsNone(result)  

    @patch('packages.sdk.src.ConfigService.get')
    @patch(f'{module_path}.Did.authorize_tx', new_callable=AsyncMock)
    @patch(f'{module_path}.uri_to_identifier', new_callable=MagicMock)
    @patch(f'{module_path}.uri_to_statement_id_and_digest', new_callable=MagicMock)
    def test_dispatch_restore_to_chain_success(self, mock_uri_to_statement_id_and_digest, 
                                               mock_uri_to_identifier, mock_authorize_tx, mock_config):
        """Test dispatch_restore_to_chain success scenario."""
        # Mock return values
        mock_api = MagicMock()
        mock_config.return_value = mock_api
        mock_uri_to_identifier.return_value = 'mock_authorization_id'
        mock_uri_to_statement_id_and_digest.return_value = {'identifier': 'mock_statement_id'}
        mock_api.compose_call.return_value = 'mock_composed_tx'
        mock_authorize_tx.return_value = 'authorized_extrinsic'
        mock_api.create_signed_extrinsic.return_value = 'signed_extrinsic'
        
        
        # Inputs
        statement_uri = STMT_URI
        creator_uri = CREATOR_URI
        authorization_uri = AUTHORIZATION_URI
        
        # Call the function
        asyncio.run(Cord.Statement.statement_chain.dispatch_restore_to_chain(
            statement_uri, creator_uri, AUTHOR_ACCOUNT, authorization_uri, SIGN_CALLBACK
        ))
        
        # Assertions to ensure the expected flow
        mock_config.assert_called_once_with('api')
        mock_uri_to_identifier.assert_called_once_with(authorization_uri)
        mock_uri_to_statement_id_and_digest.assert_called_once_with(statement_uri)
        mock_api.compose_call.assert_called_once_with(
            call_module='Statement',
            call_function='restore',
            call_params={
                'statement_id': 'mock_statement_id',
                'authorization': 'mock_authorization_id'
            }
        )
        mock_authorize_tx.assert_called_once_with(
            creator_uri, 'mock_composed_tx', SIGN_CALLBACK, AUTHOR_ACCOUNT.ss58_address
        )
        mock_api.create_signed_extrinsic.assert_called_once_with('authorized_extrinsic', AUTHOR_ACCOUNT)
        mock_api.submit_extrinsic.assert_called_once_with('signed_extrinsic', wait_for_inclusion=True)

    @patch('packages.sdk.src.ConfigService.get')
    @patch(f'{module_path}.Did.authorize_tx', new_callable=AsyncMock)
    @patch(f'{module_path}.uri_to_identifier', new_callable=MagicMock)
    @patch(f'{module_path}.uri_to_statement_id_and_digest', new_callable=MagicMock)
    def test_dispatch_restore_to_chain_failure(self, mock_uri_to_statement_id_and_digest, 
                                               mock_uri_to_identifier, mock_authorize_tx, mock_config):
        """Test dispatch_restore_to_chain failure scenario."""
        # Mock return values
        mock_api = MagicMock()
        mock_config.return_value = mock_api
        mock_uri_to_identifier.return_value = 'mock_authorization_id'
        mock_uri_to_statement_id_and_digest.return_value = {'identifier': 'mock_statement_id'}
        mock_api.compose_call.return_value = 'mock_composed_tx'
        mock_authorize_tx.return_value = 'authorized_extrinsic'
        mock_api.create_signed_extrinsic.return_value = 'signed_extrinsic'

        # Simulate an error during the extrinsic submission
        mock_api.submit_extrinsic.side_effect = Exception('Submit extrinsic failed')
        
        # Inputs
        statement_uri = STMT_URI
        creator_uri = CREATOR_URI
        authorization_uri = AUTHORIZATION_URI
        
        # Ensure the function raises CordDispatchError
        with self.assertRaises(Errors.CordDispatchError) as context:
            asyncio.run(Cord.Statement.statement_chain.dispatch_restore_to_chain(
                statement_uri, creator_uri, AUTHOR_ACCOUNT, authorization_uri, SIGN_CALLBACK
            ))

        self.assertIn('Error dispatching to chain', str(context.exception))

        # Ensure the proper flow up to the failure point
        mock_config.assert_called_once_with('api')
        mock_uri_to_identifier.assert_called_once_with(authorization_uri)
        mock_uri_to_statement_id_and_digest.assert_called_once_with(statement_uri)
        mock_api.compose_call.assert_called_once_with(
            call_module='Statement',
            call_function='restore',
            call_params={
                'statement_id': 'mock_statement_id',
                'authorization': 'mock_authorization_id'
            }
        )
        mock_authorize_tx.assert_called_once_with(
            creator_uri, 'mock_composed_tx', SIGN_CALLBACK, AUTHOR_ACCOUNT.ss58_address
        )
        mock_api.create_signed_extrinsic.assert_called_once_with('authorized_extrinsic', AUTHOR_ACCOUNT)
        mock_api.submit_extrinsic.assert_called_once_with('signed_extrinsic', wait_for_inclusion=True)
    

if __name__ == '__main__':
    unittest.main()
