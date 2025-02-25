#!/usr/bin/env python3

import sys
from BitVector import *

AES_modulus = BitVector(bitstring='100011011')

class AES:
    def __init__(self, keyfile: str) -> None:
        # Initialize AES object with key from file
        with open(keyfile, 'r') as f:
            key = f.read().strip()
        # Pad key if less than 32 bytes (256 bits)
        key = key + '0' * (32 - len(key)) if len(key) < 32 else key[:32]
        self.key_bv = BitVector(textstring=key)
        # Generate key schedule
        self.key_words = self.gen_key_schedule_256(self.key_bv)
        # Generate substitution tables
        self.sbox = self.gen_subbytes_table()
        self.inv_sbox = self.gen_inv_subbytes_table()
        
    def encrypt(self, plaintext: str, ciphertext: str) -> None:
        # Read plaintext file
        with open(plaintext, 'r') as f:
            text = f.read()
        
        # Convert text to BitVector
        bv = BitVector(textstring=text)
        
        # Pad if not multiple of 128 bits
        if len(bv) % 128 != 0:
            bv = bv + BitVector(intVal=0, size=(128 - (len(bv) % 128)))
            
        # Process each 128-bit block
        encrypted_blocks = []
        for i in range(0, len(bv), 128):
            block = bv[i:i+128]
            encrypted_block = self.encrypt_block(block)
            encrypted_blocks.append(encrypted_block)
            
        # Write ciphertext to file as hex string
        with open(ciphertext, 'w') as f:
            for block in encrypted_blocks:
                f.write(block.get_bitvector_in_hex())
    
    def decrypt(self, ciphertext: str, decrypted: str) -> None:
        # Read ciphertext hex string
        with open(ciphertext, 'r') as f:
            hex_str = f.read().strip()
            
        # Convert hex to BitVector blocks
        bv = BitVector(hexstring=hex_str)
        decrypted_blocks = []
        
        # Process each 128-bit block
        for i in range(0, len(bv), 128):
            block = bv[i:i+128]
            decrypted_block = self.decrypt_block(block)
            decrypted_blocks.append(decrypted_block)
            
        # Convert back to text and write to file
        decrypted_text = ''
        for block in decrypted_blocks:
            decrypted_text += block.get_bitvector_in_ascii()
            
        with open(decrypted, 'w') as f:
            f.write(decrypted_text)

    def encrypt_block(self, block: BitVector) -> BitVector:
        state = [[0 for x in range(4)] for x in range(4)]
        
        # Initial state array from input block
        for i in range(4):
            for j in range(4):
                state[j][i] = block[32*i + 8*j:32*i + 8*(j+1)]
                
        # Initial round - just add round key
        state = self.add_round_key(state, self.key_words[0:4])
        
        # Main rounds
        for round in range(1, 14):
            state = self.sub_bytes(state)
            state = self.shift_rows(state)
            state = self.mix_columns(state)
            state = self.add_round_key(state, self.key_words[4*round:4*(round+1)])
            
        # Final round - no mix columns
        state = self.sub_bytes(state)
        state = self.shift_rows(state)
        state = self.add_round_key(state, self.key_words[56:60])
        
        # Convert state array back to 128-bit block
        output = BitVector(size=0)
        for i in range(4):
            for j in range(4):
                output += state[j][i]
                
        return output

    def decrypt_block(self, block: BitVector) -> BitVector:
        state = [[0 for x in range(4)] for x in range(4)]
        
        # Initial state array from input block
        for i in range(4):
            for j in range(4):
                state[j][i] = block[32*i + 8*j:32*i + 8*(j+1)]
                
        # Initial round - just add round key
        state = self.add_round_key(state, self.key_words[56:60])
        
        # Main rounds
        for round in range(13, 0, -1):
            state = self.inv_shift_rows(state)
            state = self.inv_sub_bytes(state)
            state = self.add_round_key(state, self.key_words[4*round:4*(round+1)])
            state = self.inv_mix_columns(state)
            
        # Final round - no mix columns
        state = self.inv_shift_rows(state)
        state = self.inv_sub_bytes(state)
        state = self.add_round_key(state, self.key_words[0:4])
        
        # Convert state array back to 128-bit block
        output = BitVector(size=0)
        for i in range(4):
            for j in range(4):
                output += state[j][i]
                
        return output

    def sub_bytes(self, state):
        for i in range(4):
            for j in range(4):
                state[i][j] = BitVector(intVal=self.sbox[int(state[i][j])], size=8)
        return state

    def inv_sub_bytes(self, state):
        for i in range(4):
            for j in range(4):
                state[i][j] = BitVector(intVal=self.inv_sbox[int(state[i][j])], size=8)
        return state

    def shift_rows(self, state):
        for i in range(4):
            state[i] = state[i][i:] + state[i][:i]
        return state

    def inv_shift_rows(self, state):
        for i in range(4):
            state[i] = state[i][-i:] + state[i][:-i]
        return state

    def mix_columns(self, state):
        for i in range(4):
            col = [state[j][i] for j in range(4)]
            col = self.mix_single_column(col)
            for j in range(4):
                state[j][i] = col[j]
        return state

    def inv_mix_columns(self, state):
        for i in range(4):
            col = [state[j][i] for j in range(4)]
            col = self.inv_mix_single_column(col)
            for j in range(4):
                state[j][i] = col[j]
        return state

    def mix_single_column(self, col):
        temp = col.copy()
        col[0] = temp[0].gf_multiply_modular(BitVector(intVal=2), AES_modulus, 8) ^ \
                temp[1].gf_multiply_modular(BitVector(intVal=3), AES_modulus, 8) ^ \
                temp[2] ^ temp[3]
        col[1] = temp[0] ^ \
                temp[1].gf_multiply_modular(BitVector(intVal=2), AES_modulus, 8) ^ \
                temp[2].gf_multiply_modular(BitVector(intVal=3), AES_modulus, 8) ^ \
                temp[3]
        col[2] = temp[0] ^ temp[1] ^ \
                temp[2].gf_multiply_modular(BitVector(intVal=2), AES_modulus, 8) ^ \
                temp[3].gf_multiply_modular(BitVector(intVal=3), AES_modulus, 8)
        col[3] = temp[0].gf_multiply_modular(BitVector(intVal=3), AES_modulus, 8) ^ \
                temp[1] ^ temp[2] ^ \
                temp[3].gf_multiply_modular(BitVector(intVal=2), AES_modulus, 8)
        return col

    def inv_mix_single_column(self, col):
        temp = col.copy()
        col[0] = temp[0].gf_multiply_modular(BitVector(intVal=0x0e), AES_modulus, 8) ^ \
                temp[1].gf_multiply_modular(BitVector(intVal=0x0b), AES_modulus, 8) ^ \
                temp[2].gf_multiply_modular(BitVector(intVal=0x0d), AES_modulus, 8) ^ \
                temp[3].gf_multiply_modular(BitVector(intVal=0x09), AES_modulus, 8)
        col[1] = temp[0].gf_multiply_modular(BitVector(intVal=0x09), AES_modulus, 8) ^ \
                temp[1].gf_multiply_modular(BitVector(intVal=0x0e), AES_modulus, 8) ^ \
                temp[2].gf_multiply_modular(BitVector(intVal=0x0b), AES_modulus, 8) ^ \
                temp[3].gf_multiply_modular(BitVector(intVal=0x0d), AES_modulus, 8)
        col[2] = temp[0].gf_multiply_modular(BitVector(intVal=0x0d), AES_modulus, 8) ^ \
                temp[1].gf_multiply_modular(BitVector(intVal=0x09), AES_modulus, 8) ^ \
                temp[2].gf_multiply_modular(BitVector(intVal=0x0e), AES_modulus, 8) ^ \
                temp[3].gf_multiply_modular(BitVector(intVal=0x0b), AES_modulus, 8)
        col[3] = temp[0].gf_multiply_modular(BitVector(intVal=0x0b), AES_modulus, 8) ^ \
                temp[1].gf_multiply_modular(BitVector(intVal=0x0d), AES_modulus, 8) ^ \
                temp[2].gf_multiply_modular(BitVector(intVal=0x09), AES_modulus, 8) ^ \
                temp[3].gf_multiply_modular(BitVector(intVal=0x0e), AES_modulus, 8)
        return col

    def add_round_key(self, state, round_key):
        for i in range(4):
            for j in range(4):
                state[j][i] ^= round_key[i][8*j:8*(j+1)]
        return state

    def gen_subbytes_table(self):
        subBytesTable = []
        c = BitVector(bitstring='01100011')
        for i in range(0, 256):
            a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
            a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
            a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
            subBytesTable.append(int(a))
        return subBytesTable

    def gen_inv_subbytes_table(self):
        invSubBytesTable = []
        d = BitVector(bitstring='00000101')
        for i in range(0, 256):
            b = BitVector(intVal=i, size=8)
            b1,b2,b3 = [b.deep_copy() for x in range(3)]
            b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
            check = b.gf_MI(AES_modulus, 8)
            b = check if isinstance(check, BitVector) else 0
            invSubBytesTable.append(int(b))
        return invSubBytesTable

    def gee(self, keyword, round_constant, byte_sub_table):
        '''The g() function used for generating round keys.'''
        rotated_word = keyword.deep_copy()
        rotated_word << 8
        newword = BitVector(size = 0)
        for i in range(4):
            newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
        newword[:8] ^= round_constant
        round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8)
        return newword, round_constant

    def gen_key_schedule_256(self, key_bv):
        byte_sub_table = self.gen_subbytes_table()
        key_words = [None for i in range(60)]
        round_constant = BitVector(intVal = 0x01, size=8)
        for i in range(8):
            key_words[i] = key_bv[i*32 : i*32 + 32]
        for i in range(8,60):
            if i%8 == 0:
                kwd, round_constant = self.gee(key_words[i-1], round_constant, byte_sub_table)
                key_words[i] = key_words[i-8] ^ kwd
            elif (i - (i//8)*8) < 4:
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            elif (i - (i//8)*8) == 4:
                key_words[i] = BitVector(size = 0)
                for j in range(4):
                    key_words[i] += BitVector(intVal = byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
                key_words[i] ^= key_words[i-8]
            elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            else:
                sys.exit("error in key scheduling algo for i = %d" % i)
        return key_words

if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit("Incorrect number of command line arguments")

    if sys.argv[1] == "-e":
        # Encryption mode
        cipher = AES(keyfile=sys.argv[3])
        cipher.encrypt(plaintext=sys.argv[2], ciphertext=sys.argv[4])
    elif sys.argv[1] == "-d":
        # Decryption mode
        cipher = AES(keyfile=sys.argv[3])
        cipher.decrypt(ciphertext=sys.argv[2], decrypted=sys.argv[4])
    else:
        sys.exit("Incorrect Command-Line Syntax")