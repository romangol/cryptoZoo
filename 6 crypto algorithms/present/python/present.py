# PRESENT cipher Python implementation
# Version: 2.0
# Date: 2017-04-15
# Author: Liarod.v.RomanGol
#
# =============================================================================

""" PRESENT block cipher implementation
fully based on standard specifications: http://www.crypto.ruhr-uni-bochum.de/imperia/md/content/texte/publications/conferences/present_ches2007.pdf
test vectors: http://www.crypto.ruhr-uni-bochum.de/imperia/md/content/texte/publications/conferences/slides/present_testvectors.zip
"""

#        0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f
Sbox= [0xc,0x5,0x6,0xb,0x9,0x0,0xa,0xd,0x3,0xe,0xf,0x8,0x4,0x7,0x1,0x2]
Sbox_inv = [Sbox.index(x) for x in xrange(16)]
PBox = [0,16,32,48,1,17,33,49,2,18,34,50,3,19,35,51,
        4,20,36,52,5,21,37,53,6,22,38,54,7,23,39,55,
        8,24,40,56,9,25,41,57,10,26,42,58,11,27,43,59,
        12,28,44,60,13,29,45,61,14,30,46,62,15,31,47,63]
PBox_inv = [PBox.index(x) for x in xrange(64)]

def generateRoundkeys80(key,rounds):
    """Generate the roundkeys for a 80-bit key

    Input:
            key:    the key as a 80-bit integer
            rounds: the number of rounds as an integer
    Output: list of 64-bit roundkeys as integers"""
    roundkeys = []
    for i in xrange(1,rounds+1): # (K1 ... K32)
		# rawkey: used in comments to show what happens at bitlevel
		# rawKey[0:64]
		roundkeys.append(key >>16)
		#1. Shift
		#rawKey[19:len(rawKey)]+rawKey[0:19]
		key = ((key & (2**19-1)) << 61) + (key >> 19)
		#2. SBox
		#rawKey[76:80] = S(rawKey[76:80])
		key = (Sbox[key >> 76] << 76)+(key & (2**76-1))
		#3. Salt
		#rawKey[15:20] ^ i
		key ^= i << 15
    return roundkeys

def generateRoundkeys128(key,rounds):
	"""Generate the roundkeys for a 128-bit key

	Input:
	        key:    the key as a 128-bit integer
	        rounds: the number of rounds as an integer
	Output: list of 64-bit roundkeys as integers"""
	roundkeys = []
	for i in xrange(1,rounds+1): # (K1 ... K32)
		# rawkey: used in comments to show what happens at bitlevel
		roundkeys.append(key >>64)
		#1. Shift
		key = ((key & (2**67-1)) << 61) + (key >> 67)
		#2. SBox
		key = (Sbox[key >> 124] << 124)+(Sbox[(key >> 120) & 0xF] << 120)+(key & (2**120-1))
		#3. Salt
		#rawKey[62:67] ^ i
		key ^= i << 62
	return roundkeys

def key_xor(block,roundkey):
        return block ^ roundkey

def substitution(block):
	"""SBox function for encryption

	Input:  64-bit integer
	Output: 64-bit integer"""

	output = 0
	for i in xrange(16):
		output += Sbox[( block >> (i*4)) & 0xF] << (i*4)
	return output

def substitution_dec(block):
	"""Inverse SBox function for decryption

	Input:  64-bit integer
	Output: 64-bit integer"""
	output = 0
	for i in xrange(16):
		output += Sbox_inv[( block >> (i*4)) & 0xF] << (i*4)
	return output

def permutation(block):
	"""Permutation layer for encryption

	Input:  64-bit integer
	Output: 64-bit integer"""
	output = 0
	for i in xrange(64):
		output += ((block >> i) & 0x01) << PBox[i]
	return output

def permutation_dec(block):
	"""Permutation layer for decryption

	Input:  64-bit integer
	Output: 64-bit integer"""
	output = 0
	for i in xrange(64):
		output += ((block >> i) & 0x01) << PBox_inv[i]
	return output

def rkey_gen(keyStr, rounds):
	if len(keyStr) == 20:
		rkeys = generateRoundkeys80(int(keyStr, 16), rounds)
	elif len(keyStr) == 32:
		rkeys = generateRoundkeys128(int(keyStr, 16), rounds)
	else:
		raise ValueError, "Key must be a 128-bit or 80-bit rawstring"
	return rkeys

def enc(block, rkeys, rounds):
	state = block
	for i in xrange (rounds):
		state = key_xor(state, rkeys[i])
		state = substitution(state)
		state = permutation(state)
	cipher = key_xor(state, rkeys[-1])
	return cipher
	
def dec(block, rkeys, rounds):
	state = block
	for i in xrange (rounds):
		state = key_xor(state, rkeys[-i-1])
		state = permutation_dec(state)
		state = substitution_dec(state)
	decipher = key_xor(state, rkeys[0])
	return decipher


class Present:
	def __init__(self, keyStr, rounds = 32):
		# rounds: the number of rounds as an integer, 32 by default
		self.rounds = rounds 
		
		# key:    the key as a 128-bit or 80-bit rawstring
		self.roundkeys = rkey_gen(keyStr, rounds)
		
		self.blockSize = 8

	def encrypt(self, plaintext, mode):
		if not mode in ["ECB", "CBC", "OFB", "CFB"]:
			raise ValueError, "unknown mode"
		if len(plaintext) == 0:
			return ""

		if mode == "ECB":
			if len(plaintext) % (self.blockSize * 2) != 0:
				raise ValueError, "illegal length of plaintext"
			r = ""
			for i in xrange( len(plaintext) / (self.blockSize * 2) ):
				block = int( plaintext[i * self.blockSize * 2 : (i + 1) * self.blockSize * 2], 16 )
				r += '%0*x' % (self.blockSize * 2, enc(block, self.roundkeys, self.rounds - 1))
			return r

	def decrypt(self, ciphertext, mode):
		if not mode in ["ECB", "CBC", "OFB", "CFB"]:
			raise ValueError, "unknown mode"
		if len(ciphertext) == 0:
			return ""

		if mode == "ECB":
			if len(ciphertext) % (self.blockSize * 2) != 0:
				raise ValueError, "illegal length of plaintext"
			r = ""
			for i in xrange( len(ciphertext) / (self.blockSize * 2) ):
				block = int( ciphertext[i * self.blockSize * 2 : (i + 1) * self.blockSize * 2], 16 )
				r += '%0*x' % (self.blockSize * 2, dec(block, self.roundkeys, self.rounds - 1))
			return r

if __name__ == "__main__":
	key80 = "00000000000000000000"
	plain = "0000000000000000" * 2
	mode = "ECB"
	prs = Present(key80)
	cipher = prs.encrypt(plain, mode) # '5579c1387b228445'
	print cipher
	print prs.decrypt(cipher, mode)

	key128 = "0123456789abcdef0123456789abcdef"
	plain = "0123456789abcdef" * 3
	prs = Present(key128)
	cipher = prs.encrypt(plain, mode) # '0e9d28685e671dd6'
	print cipher
	print prs.decrypt(cipher, mode)
	
