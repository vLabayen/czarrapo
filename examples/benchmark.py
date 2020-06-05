import contextlib
import filecmp
import os
import shutil
import sys
import subprocess
import time

from giltzarrapo import Giltzarrapo

def human_readable(num, suffix='B'):
	for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
		if abs(num) < 1024.0:
			return "%3.1f %s%s" % (num, unit, suffix)
		num /= 1024.0
	return "%.1f %s%s" % (num, 'Yi', suffix)

def mean(a):
	return sum(a)/len(a)

def loading_bar(val, mx):

	width = 60

	progress = int((val/mx)*width)
	max_progress = int(((mx-1)/mx)*width)

	print("#"*progress, end="")
	print(" "*(max_progress - progress)+ "|", end="\r")

if __name__ == '__main__':

	try:
		NTESTS = 10
		FILE_SIZE = "10M"
		NUM_DECIMALS = 3

		# Get current and parent directories
		current_directory = os.path.dirname(os.path.realpath(__file__))
		upper_directory = os.path.dirname(current_directory)

		# Dynamic library path
		dynamic_library = os.path.join(upper_directory, "bin", "czarrapo.so")
		if not os.path.isfile(dynamic_library):
			sys.exit("[-] Dynamic library file not found. Use 'make shared' or 'make all'.")

		# Temporary test files
		pubkey = os.path.join(current_directory, "czarrapo_rsa.pub")
		privkey = os.path.join(current_directory, "czarrapo_rsa")
		plaintext_file = os.path.join(current_directory, "tmp.txt")
		encrypted_file = os.path.join(current_directory, "tmp.crypt")
		decrypted_file = os.path.join(current_directory, "tmp.decrypt")

		# Bash command to generate a test file
		GENERATE_FILE = "bash {} {} {}".format(
			os.path.join(upper_directory, "test", "generate_file.bash"), FILE_SIZE, plaintext_file
		)

		# Stats
		enc_time = []
		dec_time = []
		enc_throughput = []
		dec_throughput = []
		results = []

		print(" *** RUNNING {} TESTS ***".format(NTESTS))
		print(" *** Using files with size: {} ***".format(FILE_SIZE))

		# Generate RSA keypair and init context
		gz = Giltzarrapo(dynamic_library, pubkey, privkey, passphrase="asdf", password="1234", fast_mode=True, generate_RSA_keypair=True)

		# Perform tests
		for i in range(NTESTS):
			
			loading_bar(i, NTESTS)

			subprocess.run(GENERATE_FILE.split())
			t_start = time.perf_counter()

			gz.encrypt(plaintext_file, encrypted_file)
			t_encrypt = time.perf_counter()

			gz.decrypt(encrypted_file, decrypted_file)
			t_decrypt = time.perf_counter()

			enc_file_size = os.path.getsize(encrypted_file)
			dec_file_size = os.path.getsize(decrypted_file)

			enc_time.append(t_encrypt - t_start)
			dec_time.append(t_decrypt - t_encrypt)
			enc_throughput.append( enc_file_size/(t_encrypt - t_start) )
			dec_throughput.append( dec_file_size/(t_decrypt - t_encrypt) )
			results.append(filecmp.cmp(plaintext_file, decrypted_file))

		print("")

		print("[*] Successful tests: {}/{}".format(
			sum(result for result in results if result), NTESTS
		))

		# Total time
		print("[*] Total encryption time: {} seconds ({} files/second)".format(
			round(sum(enc_time), NUM_DECIMALS), round(NTESTS/sum(enc_time), NUM_DECIMALS)
		))
		print("[*] Total decryption time: {} seconds ({} files/second)".format(
			round(sum(dec_time), NUM_DECIMALS), round(NTESTS/sum(dec_time), NUM_DECIMALS)	
		))

		# Per-test time
		print("[*] Encryption time: avg: {}; max: {}; min: {}".format(
			round(mean(enc_time), NUM_DECIMALS), round(max(enc_time), NUM_DECIMALS), round(min(enc_time), NUM_DECIMALS)
		))
		print("[*] Decryption time: avg: {}; max: {}; min: {}".format(
			round(mean(dec_time), NUM_DECIMALS), round(max(dec_time), NUM_DECIMALS), round(min(dec_time), NUM_DECIMALS)
		))

		# Throughput
		print("[*] Encryption throughput: avg: {}/s; max: {}/s; min: {}/s".format(
			human_readable(mean(enc_throughput)), human_readable(max(enc_throughput)), human_readable(min(enc_throughput))
		))
		print("[*] Decryption throughput: avg: {}/s; max: {}/s; min: {}/s".format(
			human_readable(mean(dec_throughput)), human_readable(max(dec_throughput)), human_readable(min(dec_throughput))
		))

	except KeyboardInterrupt:
		pass

	finally:
		# Remove whatever test files exist
		with contextlib.suppress(OSError), contextlib.suppress(NameError):
			os.remove(pubkey)
			os.remove(privkey)
			os.remove(plaintext_file)
			os.remove(encrypted_file)
			os.remove(decrypted_file)
			shutil.rmtree(os.path.join(current_directory, "__pycache__"))


