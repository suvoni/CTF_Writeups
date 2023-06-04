import time
from pwn import *
from PIL import Image
from io import BytesIO
from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes

def encrypt_image(image, key):
    perm_table = {0: (0, 1, 2), 1: (0, 2, 1), 2: (1, 0, 2), 3: (1, 2, 0), 4: (2, 0, 1), 5: (2, 1, 0)}
    size = image.size[0] * image.size[1]
    assert(size == len(key))
    pixels = list(image.getdata())

    for i in range(len(pixels)):
        p = pixels[i]
        kbyte = key[i]
        
        color = [p[i]^255 if kbyte & (1 << i) else p[i] for i in range(3)]  
        (r,g,b) = perm_table[int(kbyte) % 6]
        pixels[i] = (color[r], color[g], color[b])
 
    image.putdata(pixels)
    bs = BytesIO()
    image.save(bs, format=flag_file[-3:])

    return b64encode(bs.getvalue())

def get_key_by_value(dictionary, value):
    for key, val in dictionary.items():
        if val == value:
            return key
    return None  # Value not found

p = remote('challs.dantectf.it', 31511)
sl = 0.2 #Sleep time

while True:
    
    # Get the initial lines
    line = p.recvline()
    if len(line) < 1000:
        print(line.decode('utf-8').rstrip())

    # Say yes
    if 'yours' in line.decode('utf-8').rstrip():
        time.sleep(2)
        p.sendline(b'y')
        time.sleep(2)
        line = p.recvline().decode('utf-8')
        line = p.recvline().decode('utf-8')

    if len(line) > 1000:
        
        # Read in the encrypted flag image and get its size
        line = line.decode('utf-8').rstrip().encode()
        encrypted_bytes = b64decode(line)
        bs = BytesIO(encrypted_bytes)
        flag = Image.open(bs, formats=['PNG'])

        flag_size = flag.size[0] * flag.size[1]
        print('Flag Size (in pixels): ' + str(flag_size))
        
        # Now create our own custom image to encrypt to reverse engineer the key
        # We will set all (R,G,B) values to (1,2,4) so that we can know which
        # permutation/substitution is used based upon the encrypted image
        t_image = Image.new(mode='RGBA', size=(640, 478))
        t_pixels = t_image.load()

        red_value = 1
        green_value = 2
        blue_value = 4

        for y in range(478):
            for x in range(640):
                t_pixels[x, y] = (red_value, green_value, blue_value)
        
        t_img_enc = b64encode(t_image.tobytes())
        key = get_random_bytes(flag.size[0] * flag.size[1])
        image = Image.frombytes(data=b64decode(t_img_enc), mode=flag.mode, size=flag.size)
        test_size = image.size[0] * image.size[1]

        # Send our crafted image to the server for encryption
        p.sendline(t_img_enc)
        time.sleep(sl)
        line = p.recvline().decode('utf-8').rstrip()
        print(line)
        time.sleep(sl)
        line = p.recvline().decode('utf-8').rstrip()
        print(line)
        time.sleep(sl)
        line = p.recvline().decode('utf-8').rstrip()
        print(line)
        time.sleep(sl)
        line = p.recvline().decode('utf-8').rstrip()
        print(line)
        time.sleep(1)
        line = p.recvline().decode('utf-8').rstrip()
        print(line)

        #Read in the encrypted test image and get its size
        t2_enc_bytes = b64decode(line.encode())
        t2_bs = BytesIO(t2_enc_bytes)
        t2_image = Image.open(t2_bs, formats=['PNG'])
        t2_size = t2_image.size[0] * t2_image.size[1]

        #Now recover the key from the image
        t2_pixels = list(t2_image.getdata())
        perm_table = {0: (0, 1, 2), 1: (0, 2, 1), 2: (1, 0, 2), 3: (1, 2, 0), 4: (2, 0, 1), 5: (2, 1, 0)}
        rev_table = {0: (0, 1, 2), 1: (0, 2, 1), 2: (1, 0, 2), 3: (2, 0, 1), 4: (1, 2, 0), 5: (2, 1, 0)}

        keystream = b''

        #for i in range(20):
        for i in range(len(t2_pixels)):

            #First, reverse the permutation
            (r, g, b, a) = t2_pixels[i]
            tup1 = (r, g, b)
            p1 = p2 = p3 = None
            if r == 1 or r == 254:
                p1 = 0
            elif r == 2 or r == 253:
                p1 = 1
            elif r == 4 or r == 251:
                p1 = 2
            if g == 1 or g == 254:
                p2 = 0
            elif g == 2 or g == 253:
                p2 = 1
            elif g == 4 or g == 251:
                p2 = 2
            if b == 1 or b == 254:
                p3 = 0
            elif b == 2 or b == 253:
                p3 = 1
            elif b == 4 or b == 251:
                p3 = 2
            perm = (p1, p2, p3)
            rem = get_key_by_value(perm_table, perm)
            new_pos = rev_table[rem]
            (r1, g1, b1) = (tup1[new_pos[0]], tup1[new_pos[1]], tup1[new_pos[2]])

            #Second, reverse the substitution
            key_int = 0
            if r1 == 254:
                key_int = key_int | 1
                r1 = r1 ^ 255
            if g1 == 253:
                key_int = key_int | 2
                g1 = g1 ^ 255
            if b1 == 251:
                key_int = key_int | 4
                b1 = b1 ^ 255

            while key_int % 6 != rem:
                key_int += 8

            key_byte = key_int.to_bytes(1, byteorder='big')
            keystream += key_byte
            t2_pixels[i] = (r1, g1, b1, a)
   
        #Now, use the keystream to decrypt the flag image
        flag_pixels = list(flag.getdata())
        for i in range(len(flag_pixels)):

            #First, reverse the permutation using the key
            (r, g, b, a) = flag_pixels[i]
            tup1 = (r, g, b)

            kb = keystream[i]
            new_pos = rev_table[kb % 6]

            (r1, g1, b1) = (tup1[new_pos[0]], tup1[new_pos[1]], tup1[new_pos[2]])

            #Second, reverse the substitution using the key
            if kb & 1:
                r1 = r1 ^ 255
            if kb & 2:
                g1 = g1 ^ 255
            if kb & 4:
                b1 = b1 ^ 255

            flag_pixels[i] = (r1, g1, b1, a)

        #end of while loop
        flag.putdata(flag_pixels)
        flag.save('flag.png', 'PNG')
        break

p.close()

# DANTE{Att4cks_t0_p1x3L_Encrypt3d_piCtUrES_511f0c49f8be}
