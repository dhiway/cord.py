"""
Chain bridges that connect the SDK and the CORD Chain.

Communicates with the chain via WebSockets and can listen to blocks. It exposes the `sign_and_submit_tx` function that performs the necessary tx signing.

@packageDocumentation
@module Chain
"""

from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import SubstrateRequestException
from packages.config.src.service import ConfigService
from subscriptionPromise import make_subscription_promise
from errorHandling.errorHandler import ErrorHandler
from packages.utils.src.SDKErrors import SDKError, SubscriptionsNotSupportedError
import asyncio

TxOutdated = 'Transaction is outdated'
TxPriority = 'Priority is too low:'
TxDuplicate = 'Transaction Already Imported'

def is_ready(result):
    return result['status']['isReady']

def is_in_block(result):
    return result['isInBlock']

def extrinsic_executed(result):
    return ErrorHandler.extrinsic_successful(result)

def is_finalized(result):
    return result['isFinalized']

def is_error(result):
    return result['isError'] or result['internalError']

def extrinsic_failed(result):
    return ErrorHandler.extrinsic_failed(result)

def default_resolve_on():
    return ConfigService.get('submitTxResolveOn') if ConfigService.is_set('submitTxResolveOn') else is_finalized

def convert_weight(weight):
    if 'refTime' in weight:
        # V2 or V1.5 weight
        return weight['refTime']
    # V1 weight
    return weight['weight']

async def get_max_batchable(tx):
    api = ConfigService.get('api')
    print(api)
    
    weight_info = await api.rpc.transaction_weightApi.query_weight_info(tx)
    extrinsic_ref_time = convert_weight(weight_info['weight'])
    max_ref_time = convert_weight(api.constants.system.blockWeights['maxBlock'])
    total_ref_time = max_ref_time * 75 // 100
    
    remaining_ref_time = total_ref_time
    count = 0
    
    while remaining_ref_time >= extrinsic_ref_time:
        remaining_ref_time -= extrinsic_ref_time
        count += 1
    
    return count

async def submit_signed_tx(tx, opts=None):
    opts = opts or {}
    resolve_on = opts.get('resolveOn', default_resolve_on())
    reject_on = opts.get('rejectOn', lambda result: extrinsic_failed(result) or is_error(result))
    
    api = ConfigService.get('api')
    if not api.has_subscriptions:
        raise SubscriptionsNotSupportedError()
    
    
    promise, subscription = make_subscription_promise(opts, resolve_on, reject_on)
    
    latest_result = None
    
    def callback(result):
        nonlocal latest_result
        latest_result = result
        subscription(result)
    
    unsubscribe = tx.subscribe(callback)
    
    def handle_disconnect():
        result = {
            'events': latest_result.get('events', []),
            'internalError': Exception('connection error'),
            'status': latest_result.get('status', 'future'),
            'txHash': ''
        }
        subscription(result)
    
    api.rpc.websocket_disconnect_event(handle_disconnect)
    
    try:
        return await promise
    except Exception as e:
        raise ErrorHandler.get_extrinsic_error(e) or e
    finally:
        unsubscribe()
        api.rpc.remove_websocket_disconnect_event(handle_disconnect)

async def sign_and_submit_tx(tx, signer, opts=None):
    opts = opts or {}
    nonce = opts.get('nonce', -1)
    signed_tx = tx.sign(signer, nonce=nonce)
    return await submit_signed_tx(signed_tx, opts)


'''
# Example usage
async def main():
    blockchain_rpc_ws_url = "ws://127.0.0.1:9944"

    api = await ConfigService.get('api')
    
    keypair = Keypair.create_from_uri('//Alice')
    tx = api.compose_call(
        call_module='Balances',
        call_function='transfer',
        call_params={
            'dest': '5FHneW46xGXgs5mUiveU4sbTyGBzmstxDsZnpuARwyZ5o7Dg',
            'value': 1000000000000
        }
    )
    
    result = await sign_and_submit_tx(tx, keypair)
    print(f"Transaction status: {result}")

if __name__ == "__main__":
    asyncio.run(main())
'''