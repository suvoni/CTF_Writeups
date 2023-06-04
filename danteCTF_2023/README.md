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
