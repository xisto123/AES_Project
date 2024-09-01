# aes.py
"""
AES Cipher Implementation

Este arquivo contém a classe `AES` que implementa a cifra AES, incluindo:
- Métodos de cifragem e decifragem de blocos
- Testes da implementação da cifra AES
"""

from utils import add_round_key, sub_bytes, shift_rows, mix_columns, inv_sub_bytes, inv_shift_rows, inv_mix_columns, bytesToMatrix, matrixToBytes, xor_bytes, split_blocks, increment_bytes
from constants import r_con, s_box

class AES:
    
    #Numero de rodadas baseado no tamanho da chave
    rounds_by_key_size = {16: 10, 24: 12, 32: 14}
    
    def __init__(self, master_key):
        assert len(master_key) in AES.rounds_by_key_size
        self.n_rounds = AES.rounds_by_key_size[len(master_key)]
        self._key_matrices = self._expand_key(master_key)    

    def _expand_key(self, master_key):
        key_columns = bytesToMatrix(master_key)
        iteration_size = len(master_key) // 4

        i = 1
        while len(key_columns) < (self.n_rounds + 1) * 4:
            word = list(key_columns[-1])

            if len(key_columns) % iteration_size == 0:
                word.append(word.pop(0))
                word = [s_box[b] for b in word]
                word[0] ^= r_con[i]
                i += 1
            elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
                word = [s_box[b] for b in word]

            word = xor_bytes(word, key_columns[-iteration_size])
            key_columns.append(word)

        return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]

    def encrypt_block(self, plaintext):
        assert len(plaintext) == 16
        
        plain_state = bytesToMatrix(plaintext)
        
        #rodada Inicial
        plain_state = add_round_key(plain_state, self._key_matrices[0])
        
        for i in range(1, self.n_rounds):
            sub_bytes(plain_state)
            shift_rows(plain_state)
            mix_columns(plain_state)
            add_round_key(plain_state, self._key_matrices[i])
        
        #rodada final
        sub_bytes(plain_state)
        shift_rows(plain_state)
        plain_state = add_round_key(plain_state, self._key_matrices[-1])
        
        return matrixToBytes(plain_state)

    def decrypt_block(self, ciphertext):
        assert len(ciphertext) == 16
        
        cipher_state = bytesToMatrix(ciphertext)
        cipher_state = add_round_key(cipher_state, self._key_matrices[-1])
        inv_shift_rows(cipher_state)
        inv_sub_bytes(cipher_state)
        
        for i in range(self.n_rounds - 1, 0, -1):
            add_round_key(cipher_state, self._key_matrices[i])
            inv_mix_columns(cipher_state)
            inv_shift_rows(cipher_state)
            inv_sub_bytes(cipher_state)
            
        cipher_state = add_round_key(cipher_state, self._key_matrices[0])
        
        return matrixToBytes(cipher_state)
    
    def encrypt_ctr(self, plaintext, iv):
        assert len(iv) == 16

        blocks = []
        nonce = iv
        for plaintext_block in split_blocks(plaintext, require_padding=False):
            block = xor_bytes(plaintext_block, self.encrypt_block(nonce))
            blocks.append(block)
            nonce = increment_bytes(nonce)

        return b''.join(blocks)
    
    def decrypt_ctr(self, ciphertext, iv):

        assert len(iv) == 16

        blocks = []
        nonce = iv
        for ciphertext_block in split_blocks(ciphertext, require_padding=False):
            block = xor_bytes(ciphertext_block, self.encrypt_block(nonce))
            blocks.append(block)
            nonce = increment_bytes(nonce)

        return b''.join(blocks)

class AESFileCipher:
    
    def __init__(self, key, mode, iv=None, nonce=None):
        self.aes = AES(key)
        self.mode = mode
        self.iv = iv
        self.nonce = nonce
        
    def pad(self, data):
        padding_len = 16 - len(data) % 16
        return data + bytes([padding_len] * padding_len)

    def unpad(self, data):
        padding_len = data[-1]
        return data[:-padding_len]

    def encrypt_file(self, input_file, output_file):
        with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
            while True:
                block = f_in.read(16)
                if not block:
                    break
                
                # Se o próximo bloco for vazio, significa que este é o último bloco
                next_block = f_in.read(16)
                if len(next_block) == 0:
                    block = self.pad(block)
                
                encrypted_block = self.aes.encrypt_block(block)
                f_out.write(encrypted_block)
                
                # Reposicionar o cursor para o início do bloco
                f_in.seek(-len(next_block), 1)

    def decrypt_file(self, input_file, output_file):
        with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
            prev_block = None
            while True:
                block = f_in.read(16)
                if not block:
                    break

                decrypted_block = self.aes.decrypt_block(block)
                
                if prev_block:
                    f_out.write(prev_block)
                
                prev_block = decrypted_block
            
            if prev_block:
                f_out.write(self.unpad(prev_block))

                
    def compare_files(self, file1, file2):
        with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
            while True:
                block1 = f1.read(1024)
                block2 = f2.read(1024)

                if block1 != block2:
                    return False  # Os arquivos são diferentes
                if not block1:  # Fim dos arquivos
                    break
        return True