from time import time
import itertools
import random
from Crypto.Util.number import bytes_to_long
from progress.bar import ChargingBar
from time import *
import os

SHOULD_USE_POW = True
SHOULD_USE_ANNOYING_ANIMATIONS = True

intro_dictionary = "AB"
mid_dictionary = "ABCD"

def brrr_the_strings(strings):
    print('PRINTING...')
    for i in range(len(strings)):
        print(strings[i])
    print('DONE PRINTING')
