import json
import gzip
import pprint
import os
class JSONLineWriter():
    def __init__(self, file_name, base_path, max_file_lines = 100000):
        self.base_path = base_path
        self.file_counter = 0
        self.file_name = file_name
        self.max_file_lines = max_file_lines
        self.line_counter = max_file_lines
        self.file_counter = 0
        self._open_new_file()
    

    def _open_new_file (self):
        new_file_name = self.file_name+"_"+str(self.file_counter)+".txt.gz"
        self.file = gzip.open(os.path.join(self.base_path, self.file_name, new_file_name), 'wb')
        self.file_counter += 1

    def _close_current_file(self):
        self.file.close()

    def close(self):
        self._close_current_file()
    
    def write_line(self, json_obj):
        strjson = json.dumps(json_obj)
        self.file.write(json.dumps(json_obj).encode('utf-8'))
        self.file.write('\n'.encode('utf-8'))
        self.line_counter -= 1
        if(self.line_counter == 0):
            self.line_counter = self.max_file_lines
            self._close_current_file()
            self._open_new_file()

class TransactionWriter(JSONLineWriter):

    def __init__(self, file_name, base_path, max_transactions_single_file = 100000):
        super().__init__(file_name, base_path, max_file_lines=max_transactions_single_file)
        self.operation_writer_dict = {}
    
    def __enter__(self):
        self._open_new_file()
        return self

    def __exit__(self, exc_type, exc_val, traceback):
        self.close()
        for writer in self.operation_writer_dict.values():
            writer.close()
    
    def write_line(self, transaction):
        super().write_line(transaction)
        for operation in transaction['transaction']['operations']:
            op_type = operation['type']
            if not op_type in self.operation_writer_dict:
                os.mkdir(os.path.join(self.base_path, op_type))
                self.operation_writer_dict[op_type] = JSONLineWriter(op_type, self.base_path)
            self.operation_writer_dict[op_type].write_line(operation)
        
