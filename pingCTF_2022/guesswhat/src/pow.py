import hashlib
import secrets

class NcPowser:
	def __init__(self, difficulty=20, prefix_length=17):
		self.difficulty = difficulty
		self.prefix_length = prefix_length

	def get_challenge(self):
		prefix = secrets.token_hex(self.prefix_length)
		rest = secrets.token_hex(self.difficulty - self.prefix_length)
		return prefix, rest

	def pow(self):
		prefix, rest = self.get_challenge()
		print(
			f"sha256(\"{prefix} + {'?'*(len(rest))}\") == \"{hashlib.sha256((prefix + rest).encode()).hexdigest()}\"")
		answer = input("> ")
		if hashlib.sha256((prefix + answer).encode()).hexdigest() == hashlib.sha256((prefix + rest).encode()).hexdigest():
			return True
		else:
			return False
	
	def solve_pow(self, prefix, result, unknown_count):
		from itertools import product
		possibilities = product("0123456789abcdef", repeat=unknown_count)
		for ans in possibilities:
			answer = "".join(ans)
			if hashlib.sha256((prefix + answer).encode()).hexdigest() == result:
				return answer

if __name__ == '__main__':
	print("Solving PoW...")
	nc = NcPowser()
	# sha256("dd32ded3ce6a9c864b5b2a0c364003b409 + ??????") == "e46f470c74eff9629dd828c0bfada1ff87bbeede19cdcd3fbcac8684a07b1384"
	prefix = "dd32ded3ce6a9c864b5b2a0c364003b409"
	result = "e46f470c74eff9629dd828c0bfada1ff87bbeede19cdcd3fbcac8684a07b1384"
	unknown_count = 6
	solution = nc.solve_pow(prefix, result, unknown_count)
	print(f"Solution: {solution}")
	exit(0)
