import atexit
from ctypes import *

class rsa_st(Structure):
	_fields_ = [
		("pad", c_int),
                ("version", c_long),
                ("RSA_METHOD", c_void_p),
                ("ENGINE", c_void_p),
                ("n", c_void_p),
                ("e", c_void_p),
                ("d", c_void_p)
        ]

class CzarrapoCtx(Structure):
	_fields_ = [
		("public_rsa", POINTER(rsa_st)),
		("private_rsa", POINTER(rsa_st)),
		("password", c_char_p),
		("fast", c_bool)
	]

class Giltzarrapo():

	__slots__ = ("lib", "ctx")

	def __init__(self, dynamic_library, pubkey, privkey, passphrase, password, fast_mode=True, generate_RSA_keypair=False):

		self.lib = cdll.LoadLibrary(dynamic_library)

		# Encode params
		pubkey, privkey = [c_char_p(key.encode()) if key else POINTER(c_char_p)() for key in (pubkey, privkey)]
		passphrase = c_char_p(passphrase.encode())

		if generate_RSA_keypair and pubkey and privkey:
			res = self.lib.generate_RSA_keypair(passphrase, pubkey, privkey, c_int(4096))
			if res < 0:
				raise TypeError("Error")

		self.lib.czarrapo_init.restype = POINTER(CzarrapoCtx)
		self.ctx = self.lib.czarrapo_init(
			pubkey,
			privkey,
			passphrase,
			c_char_p(password.encode()),
			c_bool(bool(fast_mode))
		)

		if not self.ctx:
			raise TypeError("Error")
			
		atexit.register(self.__free)

	def encrypt(self, infile, outfile, selected_block=-1):
		res = self.lib.czarrapo_encrypt(
			self.ctx,
			c_char_p(infile.encode()),
			c_char_p(outfile.encode()),
			c_longlong(selected_block)
		)

		if res < 0:
			raise TypeError("Error")

	def decrypt(self, infile, outfile, selected_block=-1):
		res = self.lib.czarrapo_decrypt(
			self.ctx,
			c_char_p(infile.encode()),
			c_char_p(outfile.encode()),
			c_longlong(selected_block)
		)

		if res < 0:
			raise TypeError("Error")

	def __free(self):
		if self.lib and self.ctx:
			self.lib.czarrapo_free(self.ctx)
