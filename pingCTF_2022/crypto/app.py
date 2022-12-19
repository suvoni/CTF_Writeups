from binascii import hexlify, unhexlify

printable = [chr(i) for i in range(0, 0xff)]

#FLAG = open("flag.txt").readline().strip()

encrypted = None

class Flawless:
    rounds = []
    def __init__(self, *rs):
        self.alphabet = printable
        #self.rounds[:0] = rs[0]
        print(self.rounds)
        self.l = 11
        #self.l = len(rs[0])

    def move(self, c, j):
        current_ciphertext_int = ord(encrypted[j])
        current_plaintext_int = ord(c)
        #self.alphabet[current_plaintext_int] = current_ciphertext_int

        alph_byte = ord(self.alphabet[current_plaintext_int])
        flag_byte = None
        for flag_temp in range(0, 256):
            if (flag_temp ^ alph_byte) % 255 == current_ciphertext_int:
                flag_byte = flag_temp
                print(chr(flag_byte), end="")
                break

        for i in range(len(self.alphabet)):
            self.alphabet[i] = chr((flag_byte ^ ord(self.alphabet[i])) % 0xff)
        self.current += 1

    def move_left(self):
        first = self.alphabet[0]
        self.alphabet = self.alphabet[1:]
        self.alphabet.append(first)

    def move_right(self):
        last = self.alphabet[-1]
        self.alphabet = self.alphabet[:-1]
        self.alphabet.insert(0, last)

    def press(self, c, j):
        if self.P > 0 and self.I > 0 and self.N > 0 and self.G > 0:
            self.move_left()
            self.reset_ping()
        elif ord(c) % 4 == 0:
            self.move(c, j)
        elif ord(c) % 5 == 0:
            self.move_right()
        i = printable.index(c)
        return self.alphabet[i]

    def encipher(self, text):
        self.current = 0
        self.reset_ping()
        ciphertext = ""
        j = -1
        for c in text:
            j += 1
            if c.upper() == 'P':
                self.P += 1
            elif c.upper() == 'I':
                self.I += 1
            elif c.upper() == 'N':
                self.N += 1
            elif c.upper() == 'G':
                self.G += 1
            ciphertext += self.press(c, j)
        return hexlify(ciphertext.encode()).decode()

    def reset_ping(self):
        self.P = 0
        self.I = 0
        self.N = 0
        self.G = 0

#Solution
f = open('out.txt', 'r')
encrypted = f.readline().rstrip()
encrypted = unhexlify(encrypted.encode()).decode()

very_secret_cipher_text = "Nunc at lorem mauris. Cras eu egestas diam. Sed tincidunt augue sit amet mauris accumsan bibendum. Aliquam eget dapibus massa, vitae dictum lectus. Aliquam volutpat, metus sit amet efficitur pellentesque, ipsum nibh gravida elit, non gravida magna quam vel nulla. Maecenas vestibulum ultrices lectus, eu sodales magna blandit nec. Proin sit amet urna viverra, aliquet enim vel, eleifend sapien. Sed placerat efficitur ipsum ac rhoncus. Phasellus tempor rhoncus mollis. Phasellus dapibus ultricies aliquam. Vestibulum tempor nulla quis dictum tristique. Quisque luctus ligula ac feugiat commodo. Morbi commodo viverra nunc. Morbi faucibus arcu nisl, in scelerisque lorem vulputate id. Nulla iaculis sagittis ipsum, aliquet placerat lorem cursus ac. Fusce faucibus sapien a vestibulum finibus. Nunc commodo ullamcorper nunc, ac ullamcorper orci mattis sit amet. In faucibus enim eu pellentesque congue. Interdum et malesuada fames ac ante ipsum primis in faucibus. Curabitur malesuada dui lorem. Nunc varius velit in tellus gravida, mollis porttitor dolor tristique. Interdum et malesuada fames ac ante ipsum primis in faucibus. Aliquam libero felis, ullamcorper non est nec, malesuada ultrices odio. Donec sagittis efficitur diam, non gravida lorem. Fusce bibendum mi ut libero malesuada, eu laoreet tellus dictum. Vivamus sollicitudin sed neque at rutrum. Curabitur tempus rhoncus quam eu efficitur. Aliquam maximus magna augue, at lacinia lectus vestibulum sed. Donec semper consectetur lorem. Vestibulum in sodales massa. Aenean vitae ultricies metus, sit amet vestibulum mauris. Integer orci nisi, pulvinar sit amet dui eu, fermentum lobortis nunc. Nulla luctus at lectus ac vestibulum. Nulla at ipsum tristique, tristique est eget, pharetra lectus. Morbi urna lacus."
generator = Flawless()
enciphered = generator.encipher(very_secret_cipher_text)
#print(enciphered) # out.txt
