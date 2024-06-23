import asyncio
from typing import Callable, Any, Dict, Tuple

class SDKErrors:
    class TimeoutError(Exception):
        pass

def make_subscription_promise(termination_options: Dict[str, Any]) -> Tuple[asyncio.Future, Callable]:
    """
    Helps to build a promise associated with a subscription callback through which updates can be pushed to the promise.
    This promise is resolved with the value of the latest update when a resolution criterion is met.
    It is rejected with a custom error/reason if a rejection criterion is met or on timeout (optional). Rejection takes precedence.

    :param termination_options: A dictionary containing resolveOn, rejectOn, and timeout.
    :returns: A tuple containing the promise (future) and the subscription callback.
    """
    resolve_on = termination_options.get('resolveOn')
    reject_on = termination_options.get('rejectOn')
    timeout = termination_options.get('timeout', 0)

    loop = asyncio.get_event_loop()
    future = loop.create_future()

    def subscription(value):
        if reject_on and reject_on(value):
            if not future.done():
                future.set_exception(reject_on(value))
        elif resolve_on and resolve_on(value):
            if not future.done():
                future.set_result(value)

    if timeout > 0:
        loop.call_later(timeout / 1000, lambda: future.set_exception(SDKErrors.TimeoutError()))

    return future, subscription

def make_subscription_promise_multi(args: list) -> Tuple[list, Callable]:
    """
    A wrapper around `make_subscription_promise` that helps to build multiple promises which listen to the same subscription.

    :param args: A list of dictionaries each of which provides the arguments for the creation of one promise.
    :returns: A tuple containing a list of promises and the subscription callback.
    """
    futures = []
    subscriptions = []

    for options in args:
        future, subscription = make_subscription_promise(options)
        futures.append(future)
        subscriptions.append(subscription)

    def subscription(value):
        for sub in subscriptions:
            sub(value)

    return futures, subscription

