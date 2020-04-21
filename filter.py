import json 
import pymongo
import itertools
from progress.bar import Bar
import gzip
from jsonlinewriter import TransactionWriter
from anonymize import anonymize
import argparse
import os


def grouper(iterable, n, fillvalue=None):
    args = [iter(iterable)] * n
    return itertools.zip_longest(*args, fillvalue=fillvalue)

parser = argparse.ArgumentParser()
parser.add_argument('-nas')
args = parser.parse_args()

client = pymongo.MongoClient("mongodb://marvin.nptlab.di.unimi.it")
blockchain_db = client['blockchain_db']
blocks = blockchain_db['blocks']

projection = blocks.find({"transactions":{"$exists": True, "$ne":[]}},{"transactions":1, "transaction_ids":1}, no_cursor_timeout = True)
n_blocks = blocks.count()
gblock_processed = 0
n_gblock = 0 
missed = list()
bar = Bar("Blocchi Filtrati", max=n_blocks/10000)
print('\n')
if args.nas != "":
    path_list = args.nas.split('/')
    base_path = os.getcwd()
    for dir in path_list:
        base_path = os.path.join(base_path, dir)
else:
    base_path = os.getcwd()
with TransactionWriter('transactions', base_path) as t_writer:
    for gblock in grouper(projection,10000):
        for block in filter(lambda b: b is not None, gblock):
            for tid, trin in zip(block['transaction_ids'],block['transactions']):
                transaction = dict()
                transaction['tid'] = tid
                del trin['signatures']
                del trin['ref_block_num']
                del trin['ref_block_prefix']
                transaction['transaction'] = trin
                for op in transaction['transaction']['operations']:
                        op['tid'] = tid
                        op['timestamp'] = transaction['transaction']['expiration']
                        try:
                            op = anonymize(op)
                            t_writer.write_line(transaction)
                        except Exception as e:
                            missed.append(op)
        bar.next()         
with open('failed_ops.txt','wb') as f:
    for miss in missed:
        f.write(json.dumps(miss).encode('utf-8'))
        f.write('\n'.encode('utf-8'))
bar.finish()
