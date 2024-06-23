class SDKError(Exception):
    def __init__(self, message: str = "", options: dict = None):
        super().__init__(message)
        self.name = self.__class__.__name__
        self.options = options

class SubscriptionsNotSupportedError(SDKError):
    def __init__(self, options: dict = None):
        message = (
            'This function is not available if the blockchain API does not support state or event subscriptions, '
            'use `WsProvider` to enable the complete feature set'
        )
        super().__init__(message, options)

