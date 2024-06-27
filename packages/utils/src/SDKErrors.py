class SDKError(Exception):
    def __init__(self, message: str = "", options: dict = None):
        super().__init__(message)
        self.name = self.__class__.__name__
        self.options = options

#config
class BlockchainApiMissingError(SDKError):
    def __init__(self, options: dict = None):
        message = 'Blockchain API is missing. Please set the "api" configuration.'
        super().__init__(message, options)

#network
class SubscriptionsNotSupportedError(SDKError):
    def __init__(self, options: dict = None):
        message = (
            'This function is not available if the blockchain API does not support state or event subscriptions, '
            'use `WsProvider` to enable the complete feature set'
        )
        super().__init__(message, options)

class TimeoutError(SDKError):
    def __init__(self, options: dict = None):
        message = 'Promise timed out'
        super().__init__(message, options)

#identifier errors
class InvalidURIError(SDKError):
    pass

class InvalidIdentifierError(SDKError):
    pass

class InvalidInputError(SDKError):
    pass

class Errors:
    SDKError = SDKError
    SubscriptionsNotSupportedError = SubscriptionsNotSupportedError
    InvalidURIError = InvalidURIError
    InvalidIdentifierError = InvalidIdentifierError
    TimeoutError = TimeoutError
    BlockchainApiMissingError = BlockchainApiMissingError
    InvalidInputError = InvalidInputError