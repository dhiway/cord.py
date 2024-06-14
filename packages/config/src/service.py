"""
ConfigService Module

The `ConfigService` module in the CORD SDK is responsible for managing configuration settings
necessary for the operation of various components within the SDK. It offers functionalities to set, retrieve,
and modify configurations that include connection parameters, logging levels, and other SDK-wide settings.

This module plays a crucial role in customizing the behavior of the CORD SDK to suit different operational
environments and use cases. It ensures that different parts of the SDK can access shared configuration settings
in a consistent manner, thereby facilitating a cohesive operation.

Key functionalities include:
- Setting and retrieving configuration options for the SDK.
- Resetting configurations to their default values.
- Checking the presence of specific configuration settings.

Configuration settings are crucial for the proper initialization and operation of the SDK components.
The `ConfigService` provides a centralized and convenient way to manage these settings throughout the SDK's lifecycle.

Usage of the `ConfigService` is straightforward - configurations can be set or modified at any point,
and the changes will be reflected across the SDK. This allows for dynamic adjustments according to the
application's runtime requirements.
"""

from typing import Any, Dict

class SDKErrors:
    class BlockchainApiMissingError(Exception):
        pass

class ConfigService:
    _config: Dict[str, Any] = {}

    @classmethod
    def get(cls, key: str, default: Any = None) -> Any:
        """
        Retrieves the value of a specified configuration option.

        :param key: The key of the configuration option to retrieve.
        :param default: Default value if the key is not set.
        :return: The value of the configuration option.
        :raises: BlockchainApiMissingError if the 'api' configuration is missing, or a generic error for other missing keys.
        """
        if key not in cls._config:
            if key == 'api':
                raise SDKErrors.BlockchainApiMissingError()
            else:
                raise Exception(f'GENERIC NOT CONFIGURED ERROR FOR KEY: "{key}"')
        return cls._config.get(key, default)

    @classmethod
    def set(cls, configs: Dict[str, Any]) -> None:
        """
        Sets one or more configuration options.

        :param configs: An object containing key-value pairs of configuration options.
        """
        cls._config.update(configs)

    @classmethod
    def unset(cls, key: str) -> None:
        """
        Resets a configuration option to its default value.

        :param key: The key of the configuration option to reset.
        """
        if key in cls._config:
            del cls._config[key]

    @classmethod
    def is_set(cls, key: str) -> bool:
        """
        Checks whether a specific configuration option is set.

        :param key: The key of the configuration option to check.
        :return: `True` if the configuration option is set, otherwise `False`.
        """
        return key in cls._config

