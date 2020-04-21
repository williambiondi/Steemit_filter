from aes_cipher import AESCipher
import hashlib
import json


def op_producer_reward(op):
    op['producer'] = hashlib.sha256(op['producer'].encode()).hexdigest()
    return op

def op_shutdown_witness(op):
    op['owner'] = hashlib.sha256(op['owner'].encode()).hexdigest()
    return op

def op_fill_order(op):
    op['current_owner'] = hashlib.sha256(op['current_owner'].encode()).hexdigest()
    op['open_owner'] = hashlib.sha256(op['open_owner'].encode()).hexdigest()
    return op
    
def op_fill_vesting_withdraw(op):
    op['from_account'] = hashlib.sha256(op['from_account'].encode()).hexdigest()
    op['to_account'] = hashlib.sha256(op['to_account'].encode()).hexdigest()
    return op

def op_interest(op):
    op['owner'] = hashlib.sha256(op['owner'].encode()).hexdigest()
    return op

def op_proposal_pay(op):
    op['receiver'] = hashlib.sha256(op['receiver'].encode()).hexdigest()
    return op

def op_update_proposal_votes(op):
    op['voter'] = hashlib.sha256(op['voter'].encode()).hexdigest()
    return op

def op_remove_proposal(op):
    op['creator'] = hashlib.sha256(op['creator'].encode()).hexdigest()
    return op

def op_create_proposal(op):
    op['creator'] = hashlib.sha256(op['creator'].encode()).hexdigest()
    op['receiver'] = hashlib.sha256(op['receiver'].encode()).hexdigest()
    op['permlink'] = hashlib.sha256(op['permlink'].encode()).hexdigest()
    return op

def op_decline_voting_rights(op):
    op['account'] = hashlib.sha256(op['account'].encode()).hexdigest()
    return op

def op_cancel_transfer_from_savings(op):
    op['from'] = hashlib.sha256(op['from'].encode()).hexdigest()
    return op

def op_escrow_release(op):
    op['from'] = hashlib.sha256(op['from'].encode()).hexdigest()
    op['to'] = hashlib.sha256(op['to'].encode()).hexdigest()
    op['agent'] = hashlib.sha256(op['agent'].encode()).hexdigest()
    op['who'] = hashlib.sha256(op['who'].encode()).hexdigest()
    op['receiver'] = hashlib.sha256(op['receiver'].encode()).hexdigest()
    return op

def op_escrow_dispute(op):
    op['from'] = hashlib.sha256(op['from'].encode()).hexdigest()
    op['to'] = hashlib.sha256(op['to'].encode()).hexdigest()
    op['agent'] = hashlib.sha256(op['agent'].encode()).hexdigest()
    op['who'] = hashlib.sha256(op['who'].encode()).hexdigest()
    return op
            
def op_recover_account(op):
    op['account_to_recover'] = hashlib.sha256(op['account_to_recover'].encode()).hexdigest()
    return op

def op_set_withdraw_vesting_route(op):
    op['from_account'] = hashlib.sha256(op['from_account'].encode()).hexdigest()
    op['to_account'] = hashlib.sha256(op['to_account'].encode()).hexdigest()
    return op

def op_pow(op):
    try:
        op['worker_account'] = hashlib.sha256(op['worker_account'].encode()).hexdigest()
    except KeyError:
        op['work']['value']['input']['worker_account'] = hashlib.sha256(op['work']['value']['input']['worker_account'].encode()).hexdigest()
    return op

def op_witness_set_properties(op):
    op['owner'] = hashlib.sha256(op['owner'].encode()).hexdigest()
    op['url'] = hashlib.sha256(op['url'].encode()).hexdigest()
    op['extension'] = cipher.encrypt(op['extension'])
    return op    

def op_claim_account(op):
    op['creator'] = hashlib.sha256(op['creator'].encode()).hexdigest()
    op['extension'] = cipher.encrypt(op['extension'])
    return op 

def op_escrow_transfer(op):
    op['from'] = hashlib.sha256(op['from'].encode()).hexdigest()
    op['to'] = hashlib.sha256(op['to'].encode()).hexdigest()
    op['agent'] = hashlib.sha256(op['agent'].encode()).hexdigest()
    op['json_meta'] = cipher.encrypt(op['json_meta'])
    return op

def op_change_recovery_account(op):
    op['account_to_recover'] = hashlib.sha256(op['account_to_recover'].encode()).hexdigest()
    op['new_recovery_account'] = hashlib.sha256(op['new_recovery_account'].encode()).hexdigest()
    op['extension'] = cipher.encrypt(op['extension'])
    return op

def op_account_witness_proxy(op):
    op['account'] = hashlib.sha256(op['account'].encode()).hexdigest()
    op['proxy'] = hashlib.sha256(op['proxy'].encode()).hexdigest()
    return op

def op_transfer_to_savings(op):
    op['from'] = hashlib.sha256(op['from'].encode()).hexdigest()
    op['to'] = hashlib.sha256(op['to'].encode()).hexdigest()
    return op

def op_withdraw_vesting(op):
    op['account'] = hashlib.sha256(op['account'].encode()).hexdigest()
    return op

def op_limit_order_cancel(op):
    op['owner'] = hashlib.sha256(op['owner'].encode()).hexdigest()
    return op

def op_comment_options(op):
    op['author'] = hashlib.sha256(op['author'].encode()).hexdigest()
    op['permlink'] = hashlib.sha256(op['permlink'].encode()).hexdigest()
    op['extension'] = cipher.encrypt(op['extension'])
    return op
    
def op_limit_order_create(op):
    op['owner'] = hashlib.sha256(op['owner'].encode()).hexdigest()
    return op

def op_transfer_to_vesting(op):
    op['from'] = hashlib.sha256(op['from'].encode()).hexdigest()
    op['to'] = hashlib.sha256(op['to'].encode()).hexdigest()
    return op


def op_vote(op):
    op['author'] = hashlib.sha256(op['author'].encode()).hexdigest()
    op['permlink'] = hashlib.sha256(op['permlink'].encode()).hexdigest()
    op['voter'] = hashlib.sha256(op['voter'].encode()).hexdigest()
    return op

def op_account_update(op):
    accounts = list()
    op['account'] = hashlib.sha256(op['account'].encode()).hexdigest()
    op['json_metadata'] = cipher.encrypt(op['json_metadata'])
    try:
        for account in op['posting']['account_auths']:
            accounts.append(hashlib.sha256(account[0].encode()).hexdigest())
        op['posting']['account_auths'] = accounts
    except KeyError:
        return op
    return op

def op_account_update2(op):
    op['account'] = hashlib.sha256(op['account'].encode()).hexdigest()
    op['json_metadata'] = cipher.encrypt(op['json_metadata'])
    op['posting_json_metadata'] = cipher.encrypt(op['posting_json_metadata'])
    return op

def op_delegate_vesting_shares(op):
    op['delegatee'] = hashlib.sha256(op['delegatee'].encode()).hexdigest()
    op['delegator'] = hashlib.sha256(op['delegator'].encode()).hexdigest()
    return op

def op_comment(op):
    op['author'] = hashlib.sha256(op['author'].encode()).hexdigest()
    op['body'] = cipher.encrypt(op['body'])
    op['json_metadata'] = cipher.encrypt(op['json_metadata'])
    op['parent_author'] = hashlib.sha256(op['parent_author'].encode()).hexdigest()
    op['parent_permlink'] = hashlib.sha256(op['parent_permlink'].encode()).hexdigest()
    op['permlink'] = hashlib.sha256(op['permlink'].encode()).hexdigest()
    op['title'] = cipher.encrypt(op['title'])
    return op

def cj_follow(cj):
    try:
        if len(cj) != 1:
            for e in cj :
                e[1]['follower'] = hashlib.sha256(e[1]['follower'].encode()).hexdigest()
                e[1]['following'] = hashlib.sha256(e[1]['following'].encode()).hexdigest()
            return cj
    except (KeyError, TypeError):
        try:
            cj['follower'] = hashlib.sha256(cj['follower'].encode()).hexdigest()
        except KeyError:
            return cj
        try:
            cj['following'] = hashlib.sha256(cj['following'].encode()).hexdigest()
        except KeyError:
            return cj
        return cj

def cj_reblog(cj):
    cj['account'] = hashlib.sha256(cj['account'].encode()).hexdigest()
    cj['author'] = hashlib.sha256(cj['author'].encode()).hexdigest()
    cj['permlink'] = hashlib.sha256(cj['permlink'].encode()).hexdigest()
    return cj

def cj_set_role(cj):
    cj['community'] = cipher.encrypt(cj['community'])
    cj['account'] = hashlib.sha256(cj['permlink'].encode()).hexdigest()
    return cj

def cj_set_user_title(cj):
    cj['community'] = cipher.encrypt(cj['community'])
    cj['account'] = hashlib.sha256(cj['account'].encode()).hexdigest()    
    return cj

def cj_mute_post(cj):
    cj['community'] = cipher.encrypt(cj['community'])
    cj['account'] = hashlib.sha256(cj['account'].encode()).hexdigest() 
    cj['permlink'] = hashlib.sha256(cj['permlink'].encode()).hexdigest()
    return cj

def cj_unmute_post(cj):
    cj['community'] = cipher.encrypt(cj['community'])
    cj['account'] = hashlib.sha256(cj['account'].encode()).hexdigest() 
    cj['permlink'] = hashlib.sha256(cj['permlink'].encode()).hexdigest()
    return cj

def cj_update_props(cj):
    cj['community'] = cipher.encrypt(cj['community'])
    cj['props'] = cipher.encrypt(cj['props'])
    return cj

def cj_subscribe(cj):
    cj['community'] = cipher.encrypt(cj['community'])
    return cj

def cj_pin_post(cj):
    cj['community'] = cipher.encrypt(cj['community'])
    cj['account'] = hashlib.sha256(cj['account'].encode()).hexdigest() 
    cj['permlink'] = hashlib.sha256(cj['permlink'].encode()).hexdigest()
    return cj

def cj_unsubscribe(cj):
    cj['community'] = cipher.encrypt(cj['community'])
    return cj

def cj_unpin_post(cj):
    cj['community'] = cipher.encrypt(cj['community'])
    cj['account'] = hashlib.sha256(cj['account'].encode()).hexdigest() 
    cj['permlink'] = hashlib.sha256(cj['permlink'].encode()).hexdigest()
    return cj

def cj_flag_post(cj):
    cj['community'] = cipher.encrypt(cj['community'])
    cj['account'] = hashlib.sha256(cj['account'].encode()).hexdigest() 
    cj['permlink'] = hashlib.sha256(cj['permlink'].encode()).hexdigest()
    return cj

def cj_sm_gift_cards(cj):
    cj['to'] = hashlib.sha256(cj['to'].encode()).hexdigest()  
    return cj

def cj_v2_send_voteorder(cj):
    cj['delegator'] = hashlib.sha256(cj['delegator'].encode()).hexdigest() 
    cj['author'] = hashlib.sha256(cj['author'].encode()).hexdigest() 
    cj['permlink'] = hashlib.sha256(cj['permlink'].encode()).hexdigest()
    cj['ruleset'] = cipher.encrypt(cj['ruleset'])
    return cj

def cj_v2_confirm_vote(cj):
    cj['voter'] = hashlib.sha256(cj['voter'].encode()).hexdigest() 
    return cj 

def cj_sm_gift_packs(cj):
    cj['to'] = hashlib.sha256(cj['to'].encode()).hexdigest()
    return cj

def cj_feed(cj):
    cj['profile']['profile_image'] = hashlib.sha256(cj['profile']['profile_image'].encode()).hexdigest()
    cj['profile']['name'] = hashlib.sha256(cj['profile']['name'].encode()).hexdigest()
    sha_beneficiaries = dict()
    for key in cj['game']['beneficiary']:
        sha_beneficiaries[hashlib.sha256(key.encode()).hexdigest()] = cj['game']['beneficiary'].get(key)
    cj['game']['beneficiary'] = sha_beneficiaries
    return cj

def cj_pacman_live(cj):
    cj['username'] = hashlib.sha256(cj['username'].encode()).hexdigest()
    return cj

def cj_anpigon_pets_vote(cj):
    cj['title'] = cipher.encrypt(cj['title'])
    cj['body'] = cipher.encrypt(cj['body'])
    cj['author'] = hashlib.sha256(cj['author'].encode()).hexdigest()
    cj['permlink'] = hashlib.sha256(cj['permlink'].encode()).hexdigest()
    return cj

def cj_1(cj):
    cj['name'] = hashlib.sha256(cj['name'].encode()).hexdigest()
    return cj

def cj_wise(cj):
    op['voter'] = hashlib.sha256(op['voter'].encode()).hexdigest()
    return cj

def cj_vote(cj):
    cj['account'] = hashlib.sha256(cj['account'].encode()).hexdigest()
    cj['author'] = hashlib.sha256(cj['author'].encode()).hexdigest()
    cj['permlink'] = cipher.encrypt(cj['permlink'])
    cj['app'] = hashlib.sha256(cj['app'].encode()).hexdigest
    return cj
    
def cj_ssc_mainnet1(cj):
    cj['contractName'] = hashlib.sha256(cj['contractName'].encode()).hexdigest()
    cj['contractPayload']['to'] = hashlib.sha256(cj['contractPayload']['to'].encode()).hexdigest()
    return cj

def cj_nextcolony(cj):
    cj['username'] = hashlib.sha256(cj['username'].encode()).hexdigest()
    cj['command'] = cipher.encrypt(cj['command'])
    return cj


def cj_modpost(cj):
    cj['forum'] = cipher.encrypt(cj['forum'])
    cj['topic'] = cipher.encrypt(cj['topic'])
    return cj

def cj_elb(cj):
    cj['birth_date'] = hashlib.sha256(cj['birth_date'].encode()).hexdigest()
    cj['password'] = hashlib.sha256(cj['password'].encode()).hexdigest()
    return cj   

def cj_rebloger(cj):
    cj['account'] = hashlib.sha256(cj['account'].encode()).hexdigest()
    cj['author'] = hashlib.sha256(cj['author'].encode()).hexdigest()
    cj['permlink'] = cipher.encrypt(cj['permlink'])
    return cj

def cj_storage(cj):
    cj['data'] = cipher.encrypt(cj['data'])
    try:
        cj['account'] = hashlib.sha256(cj['account'].encode()).hexdigest()
        cj['filename'] = hashlib.sha256(cj['filename'].encode()).hexdigest()
    except KeyError:
        return cj
    return cj

def cj_steemit_community(cj):
    cj['community'] = cipher.encrypt(cj['community'])
    for admin in cj['admins']:
        admin = hashlib.sha256(admin.encode()).hexdigest()
    return cj

def cj_opinion(cj):
    cj['account'] = hashlib.sha256(cj['account'].encode()).hexdigest()
    cj['permlink'] = cipher.encrypt(cj['permlink'])
    return cj

def cj_bookchain(cj):
    cj['book_name'] = cipher.encrypt(cj['test_name'])
    return cj

def cj_testchain(cj):
    cj['test_name'] = hashlib.sha256(cj['test_name'].encode()).hexdigest()
    return cj

def cj_account_history(cj):
    cj['account'] = hashlib.sha256(cj['account'].encode()).hexdigest()
    return cj

def cj_message(cj):
    cj['to'] = hashlib.sha256(cj['to'].encode()).hexdigest()
    return cj

def cj_notify(cj):
    return cj

def cj_active_user(cj):
    cj['account'] = hashlib.sha256(cj['account'].encode()).hexdigest()
    return cj


def op_custom_json(op):
    posting_auths = []
    required_auths = []
    for posting_auth in op['required_posting_auths']: 
        posting_auths.append(hashlib.sha256(posting_auth.encode()).hexdigest())
    op['required_posting_auths'] = posting_auths
    for required_auth in op['required_auths']: 
        required_auths.append(hashlib.sha256(required_auth.encode()).hexdigest())
    op['required_auths'] = required_auths
    id = op['id']
    try:
        cj = json.loads(op['json'])[1]
    except (IndexError, KeyError):
        #id = json.loads(op['json'])[0]
        cj = json.loads(op['json'])
    if not isinstance(id,str):
        id = op['id']
    if id not in dispatcher_c_json.keys():
        op['json'] = cipher.encrypt(op['json'])
        return op
    else:
        try:
            op['json'] = dispatcher_c_json[id](cj)
        except(TypeError):
            op['json'][0] = dispatcher_c_json[id](cj)
        return op

def op_request_account_recovery(op):
    op['recovery_account'] = hashlib.sha256(op['recovery_account'].encode()).hexdigest() 
    op['account_to_recover'] = hashlib.sha256(op['account_to_recover'].encode()).hexdigest() 
    return op


def op_feed_publish(op):
    op['publisher'] = hashlib.sha256(op['publisher'].encode()).hexdigest() 
    return op

def op_account_create(op):
    op['creator'] = hashlib.sha256(op['creator'].encode()).hexdigest() 
    op['new_account_name'] = hashlib.sha256(op['new_account_name'].encode()).hexdigest()
    return op

def op_delete_comment(op):
    op['author'] = hashlib.sha256(op['author'].encode()).hexdigest()
    op['permlink'] = hashlib.sha256(op['permlink'].encode()).hexdigest()
    return op

def op_account_create_delegation(op):
    op['creator'] = hashlib.sha256(op['creator'].encode()).hexdigest() 
    op['new_account_name'] = hashlib.sha256(op['new_account_name'].encode()).hexdigest()
    return op

def op_witness_update(op):
    op['owner'] = hashlib.sha256(op['owner'].encode()).hexdigest()
    op['url'] = hashlib.sha256(op['url'].encode()).hexdigest()
    return op

def op_witness_vote(op):
    op['account'] = hashlib.sha256(op['account'].encode()).hexdigest()
    op['witness'] = hashlib.sha256(op['witness'].encode()).hexdigest()
    return op

def op_convert(op):
    op['owner'] = hashlib.sha256(op['owner'].encode()).hexdigest()
    return op

def op_claim_reward(op):
    op['account'] = hashlib.sha256(op['account'].encode()).hexdigest()
    return op

def op_transfer(op):
    op['from'] = hashlib.sha256(op['from'].encode()).hexdigest()
    op['to'] = hashlib.sha256(op['to'].encode()).hexdigest()
    op['memo'] = hashlib.sha256(op['memo'].encode()).hexdigest()
    return op

def op_custom(op):
    required_auths = []
    for required_auth in op['required_auths']: 
        required_auths.append(hashlib.sha256(required_auth.encode()).hexdigest())
    op['required_auths'] = required_auths    
    return op

def op_create_claimed_account(op):
    op['creator'] = hashlib.sha256(op['creator'].encode()).hexdigest()
    op['new_account_name'] = hashlib.sha256(op['new_account_name'].encode()).hexdigest()
    return op

dispatcher_c_json = {
        'follow':cj_follow,
        'reblog':cj_reblog, 
        'setRole':cj_set_role,
        'setUserTitle':cj_set_user_title,
        'mutePost':cj_mute_post,
        'unmutePost':cj_unmute_post,
        'updateProps':cj_update_props,
        'subscribe':cj_subscribe,
        'pinPost':cj_pin_post,
        'unsubscribe':cj_unsubscribe,
        'unpinPost':cj_unpin_post,
        'flagPost': cj_flag_post,
        'sm_gift_cards':cj_sm_gift_cards,
        'v2:send_voteorder': cj_v2_send_voteorder,
        'v2:confirm_vote': cj_v2_confirm_vote,
        'feed': cj_feed,
        'sm_gift_packs': cj_sm_gift_packs,
        'pacman-live':cj_pacman_live,
        'pacman': cj_pacman_live,
        'anpigon_pets_vote': cj_anpigon_pets_vote,
        '1': cj_1,
        'wise':cj_wise,
        'booyah': cj_follow,
        'message': cj_message,
        'account_history': cj_account_history,
        'testchain': cj_testchain,
        'bookchain': cj_bookchain,
        'opinion': cj_opinion,
        'com.steemit.community': cj_steemit_community,
        'test_community': cj_steemit_community,
        'unfollow': cj_follow,
        'storage': cj_storage,
        'matrix_cover.jpg':cj_storage,
        'randomtest': cj_storage,
        'randomtest2': cj_storage,
        'somefilename': cj_storage,
        'testfile': cj_storage,
        'atesttest': cj_storage,
        'coverimage': cj_storage,
        'bitcoin_whitepaper': cj_storage,
        'cute_dogs': cj_storage,
        'myface': cj_storage,
        'game_of_life': cj_storage,
        'doge': cj_storage,
        'alex_grey_cid': cj_storage,
        'avatar_gol': cj_storage,
        'distributed_computing': cj_storage,
        'double-spend-bitcoin': cj_storage,
        'stressinyo': cj_storage,
        'SteemWhitePaper': cj_storage,
        'testthatmagic': cj_storage,
        'declaration_of_independence': cj_storage,
        'witness': cj_account_history,
        'rebloger': cj_rebloger,
        'elb': cj_elb,
        'modpost': cj_modpost,
        'nextcolony':cj_nextcolony,
        'ssc-mainnet1':cj_ssc_mainnet1,
        'vote': cj_vote,
        'active_user':cj_active_user,
        'community':cj_steemit_community,
        'notify': cj_notify,
    }

dispatcher = {
        'vote_operation' : op_vote,
        'comment_operation' : op_comment,
        'custom_json_operation' : op_custom_json,
        'feed_publish_operation' : op_feed_publish,
        'account_create_operation' : op_account_create,
        'delete_comment_operation' : op_delete_comment,
        'account_create_with_delegation_operation' : op_account_create_delegation,
        'witness_update_operation': op_witness_update,
        'account_witness_vote_operation': op_witness_vote,
        'convert_operation' : op_convert,
        'claim_reward_balance_operation' : op_claim_reward,
        'create_claimed_account_operation': op_create_claimed_account,
        'transfer_operation': op_transfer,
        'account_update_operation':op_account_update,
        'delegate_vesting_shares_operation':op_delegate_vesting_shares,
        'transfer_to_vesting_operation': op_transfer_to_vesting,
        'limit_order_create_operation': op_limit_order_create,
        'comment_options_operation': op_comment_options,
        'limit_order_cancel_operation': op_limit_order_cancel,
        'withdraw_vesting_operation': op_withdraw_vesting,
        'transfer_to_savings_operation' :op_transfer_to_savings,
        'transfer_from_savings_operation' : op_transfer_to_savings,
        'account_witness_proxy_operation' : op_account_witness_proxy,
        'change_recovery_account_operation' : op_change_recovery_account,
        'escrow_transfer_operation': op_escrow_transfer,
        'escrow_approve_operation':op_escrow_dispute,
        'claim_account_operation': op_claim_account,
        'witness_set_properties_operation' : op_witness_set_properties,
        'pow_operation': op_pow,
        'pow2_operation': op_pow,
        'set_withdraw_vesting_route_operation' : op_set_withdraw_vesting_route,
        'recover_account_operation': op_recover_account,
        'escrow_dispute_operation': op_escrow_dispute,
        'escrow_release_operation':op_escrow_release,
        'cancel_transfer_from_savings_operation': op_cancel_transfer_from_savings,
        'decline_voting_rights_operation': op_decline_voting_rights,
        'create_proposal_operation': op_create_proposal,
        'remove_proposal_operation':op_remove_proposal,
        'update_proposal_votes_operation': op_update_proposal_votes,
        'claim_reward_balance2_operation': op_claim_reward,
        'vote2_operation': op_vote,
        'proposal_pay_operation':op_proposal_pay,
        'interest_operation':op_interest,
        'fill_vesting_withdraw_operation':op_fill_vesting_withdraw,
        'fill_order_operation': op_fill_order,
        'shutdown_witness_operation': op_shutdown_witness,
        'producer_reward_operation': op_producer_reward,
        'request_account_recovery_operation': op_request_account_recovery,
        'custom_operation': op_custom,
        'limit_order_create2_operation': op_limit_order_create,
        'limit_order_cancel2_operation': op_limit_order_cancel,
        'account_update2_operation': op_account_update2
        }

cipher = AESCipher(input())

def anonymize(op):
    if op['type'] not in dispatcher.keys():
        with open('not_anonymized.txt','ab')as f:
            f.write(json.dumps(op).encode('utf-8'))
            f.write('\n'.encode('utf-8'))
    op['value'] = dispatcher[op['type']](op['value'])
    return op