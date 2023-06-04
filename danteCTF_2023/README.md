# danteCTF 2023 Writeup (Team: L3ak, 4th Place)
Competition URL: https://dantectf.it/
## Overview

| Challenge | Category | Flag |
| --------- | -------- | ---- |
| PiedPic | Crypto | DANTE{Att4cks_t0_p1x3L_Encrypt3d_piCtUrES_511f0c49f8be} |
| Almost Perfect Remote Signing | Forensics | DANTE{FLAG_REPORTING_SYSTEM} |
| StrangeBytes | Misc | DANTE{AHh9HhH0hH_ThAat_RAnsomware_maDe_m3_SaD_FFFFAAABBBBDDDD67} |

## 1) PiedPic
In this crypto challenge, we are given a Python file named ```PiedPic.py``` which takes an image as input and returns an encrypted form of it. It also provides the encrypted form of a "flag file" that we presumably must decrypt. The ```encrypt_image``` function is shown below.
```Python
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
```
A close inspection will reveal that each RGB pixel in the image is encrypted using a permutation-substitution transformation according to the bits of the key. First, the R/G/B values are negated (```p[i]^255```)if the 1st/2nd/3rd least significant bits in the key are set (1) - this is the substitution step. Next, the RGB values are swapped around according to positions specified in the ```perm_table``` based upon the remainder of ```key_byte % 6``` - this is the permutation step. The new RGB values are written back into the pixel and the process repeats for all pixels in the image. Finally, the resulting bytes are encoded in base64 and sent to the user.

To decrypt the image, we need to reverse the above process, and we also need to recover the key. We are allowed to give the program one image to encrypt for us with the _same key_ as the flag image. Therefore, we need to cleverly choose the RGB values so that we can know by looking at the encrypted version (1) which permutation was used and (2) which values were flipped. This will allow us to reconstruct the key byte (```kbyte```) to ultimately decrypt the flag image.

The method I devised to accomplish this task is to use (1,2,4) for the (R,G,B) values in every image pixel. Why use these numbers? The binary equivalent of (1,2,4) is (001, 010, 100), and the negated version of this is (110, 101, 011). Thus, for any combination of substitutions and permutations, we can find the permutation and substitution by the mapping between the original and encrypted forms.

For example, if the first byte (the "R" in RGB) is negated in the substitution step, then (1,2,4) becomes (254, 2, 4). Then, if the permutation chosen by the key is (0, 2, 1) then (254, 2, 4) becomes (254, 4, 2) (i.e., the 2nd and 3rd values are swapped). Looking at the encrypted version, we know that 254 has to correspond to 1 (reversing the substitution step) and 
