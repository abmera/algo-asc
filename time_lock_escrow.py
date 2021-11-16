import time
import base64

from datetime import datetime as dt
from datetime import timedelta as td
from algosdk.future import transaction
from algosdk import account, mnemonic, logic
from algosdk.v2client import algod
from pyteal import *
from pyteal.ast import app

'''
***************************WARNING*******************************
THIS SCRIPT IS PROVIDED FOR INFORMATIONAL PURPOSES ONLY AND
HAS NOT BEEN AUDITED FOR SECURITY
*****************************************************************
Simple script to make a Time Locked Smart Contract Escrow Account

Based on Algorand documentation examples:
https://developer.algorand.org/docs/get-details/dapps/pyteal/#building-pyteal-smart-contracts
'''

# # user declared algod connection parameters. Node must have EnableDeveloperAPI set to true in its config
algod_address = "http://localhost:4080"
algod_token = "NODE API TOKEN..."

# ONLY this account would be able to call the app and receive funds after time lock
receiver = {
    'mnemonic': "ALGORAND MNEMONIC...",
    'address' : "ADDRESS...",
}

# only used to create smart contract
creator = {
    'mnemonic': "ALGORAND MNEMONIC...",
    'address' : "ADDRESS...",
}

# Helper functions for terminal font colors
R  = lambda s: f'\x1b[31m{s}\x1b[0m'
Y  = lambda s: f'\x1b[93m{s}\x1b[0m'

# helper function to compile program source
def compile_program(client, source_code):
    compile_response = client.compile(source_code)
    print("Program:", compile_response['result'])
    print("Hash   :", compile_response['hash'])
    return base64.b64decode(compile_response['result'])

# helper function that converts a mnemonic passphrase into a private signing key
def get_private_key_from_mnemonic(mn) :
    private_key = mnemonic.to_private_key(mn)
    return private_key

# helper function that waits for a given txid to be confirmed by the network
def wait_for_confirmation(client, transaction_id, timeout):
    """
    Wait until the transaction is confirmed or rejected, or until 'timeout'
    number of rounds have passed.
    Args:
        transaction_id (str): the transaction to wait for
        timeout (int): maximum number of rounds to wait    
    Returns:
        dict: pending transaction information, or throws an error if the transaction
            is not confirmed or rejected in the next timeout rounds
    """
    start_round = client.status()["last-round"] + 1
    current_round = start_round

    while current_round < start_round + timeout:
        try:
            pending_txn = client.pending_transaction_info(transaction_id)
        except Exception:
            return 
        if pending_txn.get("confirmed-round", 0) > 0:
            return pending_txn
        elif pending_txn["pool-error"]:  
            raise Exception(
                'pool error: {}'.format(pending_txn["pool-error"]))
        client.status_after_block(current_round)                   
        current_round += 1
    raise Exception(
        'pending tx not found in timeout rounds, timeout value = : {}'.format(timeout))

def payment_transaction(algod_client, creator_mnemonic, amt, rcv):
    params = algod_client.suggested_params()
    add = mnemonic.to_public_key(creator_mnemonic)
    key = mnemonic.to_private_key(creator_mnemonic)
    unsigned_txn = transaction.PaymentTxn(add, params, rcv, amt)
    signed = unsigned_txn.sign(key)
    txid = algod_client.send_transaction(signed)
    pmtx = wait_for_confirmation(algod_client, txid , 5)
    return pmtx

# helper function that formats global state for printing
def format_state(state):
    formatted = {}
    for item in state:
        key = item['key']
        value = item['value']
        formatted_key = base64.b64decode(key).decode('utf-8')
        if value['type'] == 1:
            # byte string
            if formatted_key == 'voted':
                formatted_value = base64.b64decode(value['bytes']).decode('utf-8')
            else:
                formatted_value = value['bytes']
            formatted[formatted_key] = formatted_value
        else:
            # integer
            formatted[formatted_key] = value['uint']
    return formatted

# helper function to read app global state
def read_global_state(client, addr, app_id):
    results = client.account_info(addr)
    apps_created = results['created-apps']
    for app in apps_created:
        if app['id'] == app_id:
            return format_state(app['params']['global-state'])
    return {}

# create new application
def create_app(client, private_key, approval_program, clear_program, global_schema, local_schema, **kwargs):
    # define sender as creator
    sender = account.address_from_private_key(private_key)

    # declare on_complete as NoOp
    on_complete = transaction.OnComplete.NoOpOC.real

    # get node suggested parameters
    params = client.suggested_params()

    # create unsigned transaction
    txn = transaction.ApplicationCreateTxn(sender, params, on_complete, \
                                            approval_program, clear_program, \
                                            global_schema, local_schema, **kwargs)

    # sign transaction
    signed_txn = txn.sign(private_key)
    tx_id = signed_txn.transaction.get_txid()

    # send transaction
    client.send_transactions([signed_txn])

    # await confirmation
    wait_for_confirmation(client, tx_id, 5)

    # display results
    transaction_response = client.pending_transaction_info(tx_id)
    app_id = transaction_response['application-index']
    print("Created new app-id:", app_id)

    return app_id

# call application
def call_app(client, private_key, index, app_args, accounts=None) : 
    # declare sender
    sender = account.address_from_private_key(private_key)

    # get node suggested parameters
    params = client.suggested_params()

    # create unsigned transaction
    txn = transaction.ApplicationNoOpTxn(sender, params, index, app_args, accounts=accounts)

    # sign transaction
    signed_txn = txn.sign(private_key)
    tx_id = signed_txn.transaction.get_txid()

    # send transaction
    client.send_transactions([signed_txn])

    # await confirmation
    wait_for_confirmation(client, tx_id, 5)

    print("Application called")

def release_funds():
    '''
    docs: https://pyteal.readthedocs.io/en/latest/api.html#pyteal.InnerTxnBuilder
    '''
    prog_addr = Global.current_application_address()
    amt = Btoi(Txn.application_args[1])
    return Seq([
        InnerTxnBuilder.Begin(),
        InnerTxnBuilder.SetField(TxnField.receiver   , Addr(receiver['address'])),
        InnerTxnBuilder.SetField(TxnField.type_enum  , TxnType.Payment),
        InnerTxnBuilder.SetField(TxnField.amount     , amt),
        If(Balance(prog_addr) < amt + Int(101_000),
            InnerTxnBuilder.SetField(TxnField.close_remainder_to, Addr(receiver['address'])),
        ),
        InnerTxnBuilder.Submit(),
        Return(Int(1)),
    ])

def update_time_remaining():
    end_ts = App.globalGet(Bytes("timeout-until"))
    return Seq([
        If(Global.latest_timestamp() <= end_ts)
        .Then(App.globalPut(Bytes("timeout-remaining"), end_ts - Global.latest_timestamp()))
        .Else(App.globalPut(Bytes("timeout-remaining"), Int(0))),
        Return(Int(1)),
    ])

# Handle each possible OnCompletion type. We don't have to worry about
# handling ClearState, because the ClearStateProgram will execute in that
# case, not the ApprovalProgram.
# Approve() = Return(Int(1))
# Reject()  = Return(Int(0))
def approval_program():
    '''
    !IMPORTANT
    Begining date has to be hard-coded to get a deterministic output 
    so that anyone auditing the code could produce the same compiled program hash
    '''
    beg_time = dt(2021, 11, 16, 14, 00)             # !IMPORTANT
    end_time = beg_time + td(hours=0, minutes=15)   # !IMPORTANT
    beg_ts = int(beg_time.timestamp())
    end_ts = int(end_time.timestamp())

    print(Y(f'Begining time:\t{beg_time.strftime("%b %d %Y %H:%M:%S")} ({beg_ts})'))
    print(R(f'Ending time:\t{end_time.strftime("%b %d %Y %H:%M:%S")} ({end_ts})'))
    print(Y(f'Now time:\t{dt.fromtimestamp(time.time()//1).strftime("%b %d %Y %H:%M:%S")} ({end_ts})'))

    prog_addr = Global.current_application_address()

    withdrawal_cond = And(
        Txn.sender() == Addr(receiver['address']),              # only receiver can withdraw
        Global.latest_timestamp() > Int(end_ts),                # time lock logic
        Balance(prog_addr) >= Btoi(Txn.application_args[0]),    # anmount to withdraw passes as Arg 0
    )

    handle_noop = Cond(
        [ Txn.application_args.length() == Int(0), Err() ],
        [ Txn.application_args[0] == Bytes("update"), update_time_remaining() ],
        [ And(Txn.application_args[0] == Bytes("withdraw"), withdrawal_cond), release_funds() ],
        [ Int(1), Reject() ]
    )

    handle_creation = Seq([
        App.globalPut(Bytes("timeout-until"), Int(end_ts)),
        App.globalPut(Bytes("timeout-remaining"), Int(end_ts) - Global.latest_timestamp()),
        Approve()
    ])

    handle_optin = Seq([
        Reject()
    ])

    handle_closeout = Seq([
        Return(Int(1))
    ])

    handle_updateapp = Err()

    handle_deleteapp = Err()

    program = Cond(
        [Txn.application_id() == Int(0), handle_creation],
        [Txn.on_completion() == OnComplete.NoOp, handle_noop],
        [Txn.on_completion() == OnComplete.OptIn, handle_optin],
        [Txn.on_completion() == OnComplete.CloseOut, handle_closeout],
        [Txn.on_completion() == OnComplete.UpdateApplication, handle_updateapp],
        [Txn.on_completion() == OnComplete.DeleteApplication, handle_deleteapp]
    )
    # Mode.Application specifies that this is a smart contract
    return compileTeal(program, Mode.Application, version=5)

def clear_state_program():
    program = Return(Int(1))
    # Mode.Application specifies that this is a smart contract
    return compileTeal(program, Mode.Application, version=3)

def compile_to_teal():
    # compile program to TEAL assembly
    with open("./time_lock_escrow_approval.teal", "w") as f:
        approval_program_teal = approval_program()
        f.write(approval_program_teal)

    # compile program to TEAL assembly
    with open("./time_lock_escrow_clear.teal", "w") as f:
        clear_state_program_teal = clear_state_program()
        f.write(clear_state_program_teal)

    return approval_program_teal, clear_state_program_teal

def deploy_app(algod_client, creator_private_key):
    # declare application state storage (immutable)
    # storing two integers: (1) timestamp timeout end and (2) time remaining
    global_schema = transaction.StateSchema(num_uints=2, num_byte_slices=0)
    local_schema = transaction.StateSchema(num_uints=0, num_byte_slices=0)

    approval_program_teal, clear_state_program_teal = compile_to_teal()

    # compile program to binary
    approval_program_compiled = compile_program(algod_client, approval_program_teal)

    # compile program to binary
    clear_state_program_compiled = compile_program(algod_client, clear_state_program_teal)

    print(Y("--------------------------------------------"))
    print(Y("Deploying application......"))

    # create new application
    app_id = create_app(algod_client, creator_private_key, approval_program_compiled, clear_state_program_compiled, global_schema, local_schema)
    prog_addr = logic.get_application_address(app_id)
    print(Y(f'Application ID     : {str(app_id)}'))
    print(Y(f'Application address: {prog_addr}'))       # escrow account
    # read global state of application
    # print("Global state:", read_global_state(algod_client, account.address_from_private_key(creator_private_key), app_id))

    return app_id, prog_addr

def send_funds_to_escrow(algod_client, sender_mnemonic, amount, escrow_address):
    print(Y("--------------------------------------------"))
    print(Y("Sending funds to lock......"))
    payment_transaction(algod_client, sender_mnemonic, amount, escrow_address)

def test_call(algod_client, private_key, app_id, app_args):
    print(Y("--------------------------------------------"))
    print(Y("Calling application......"))
    # microAlgos to withdraw
    accounts = [receiver['address']]
    call_app(algod_client, private_key, app_id, app_args, accounts)

def main() :
    # initialize an algodClient
    algod_client = algod.AlgodClient(algod_token, algod_address)

    # define private keys
    creator_private_key = get_private_key_from_mnemonic(creator['mnemonic'])
    receiver_private_key = get_private_key_from_mnemonic(receiver['mnemonic'])

    # `app_id` will be use to call the application and withdraw funds
    # `prog_addr` is the escrow account that will hold the locked funds
    app_id, prog_addr = deploy_app(algod_client, creator_private_key)

    funding_amount = 1_002_000
    send_funds_to_escrow(algod_client, creator['mnemonic'], funding_amount, prog_addr)

    # call the application, and try to withdraw funds
    # will fail if timeout is still active
    withdrawal_amount = 500_000
    test_call(algod_client, receiver_private_key, app_id, app_args = ['update'])
    test_call(algod_client, receiver_private_key, app_id, app_args = ['withdraw', withdrawal_amount])

if __name__ == '__main__':
    # compile_to_teal()
    main()
