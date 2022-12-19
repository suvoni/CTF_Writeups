import base64

plaintext = "Hi Alice, I'm Bob. I'm sending you a secret message. I hope you can decrypt it."

def decrypt(message):
    flag = ""
    message = base64.b64decode(message).decode()
    for i in range(len(message)):
        for key_char in range(0, 256):
            if plaintext[i] == chr((256 + ord(message[i]) - key_char) % 256):
                flag += chr(key_char)
                break
    print(flag)
    return

f = open("out.txt", "r")
ciphertext = f.readline().rstrip()
decrypt(ciphertext)
