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

#DID errors
class InvalidDidFormatError(SDKError):
    def __init__(self, did: str, options: dict = None):
        message = f'Not a valid CORD DID "{did}"'
        super().__init__(message, options)

class DidError(SDKError):
    pass

class AddressInvalidError(SDKError):
    def __init__(self, id,  options: dict = None):
        if id and type:
            message = f'Provided {type} identifier "{id}" is invalid'
        elif id:
            message = f'Provided identifier "{id}" is invalid'
        else:
            message = 'Provided identifier is invalid'
        super().__init__(message, options)

class AddressTypeError(SDKError):
    pass
class Errors:
    SDKError = SDKError
    SubscriptionsNotSupportedError = SubscriptionsNotSupportedError
    InvalidURIError = InvalidURIError
    InvalidIdentifierError = InvalidIdentifierError
    TimeoutError = TimeoutError
    BlockchainApiMissingError = BlockchainApiMissingError
    InvalidInputError = InvalidInputError
    InvalidDidFormatError = InvalidDidFormatError
    DidError = DidError
    AddressInvalidError = AddressInvalidError
    AddressTypeError = AddressTypeError