from src.common import *
from flag import flag

assert(len(flag) == 2**(2**2))

def part3_():
    print("Ok. This is kinda spooky. This time I will show you that I know everything, and you will have to prove me wrong in order to get the flag.")

def part3():
    real_flag = flag[5:][:-1]
    if (SHOULD_USE_ANNOYING_ANIMATIONS):
        for i in ChargingBar("Loading flags", max=64, check_tty=False).iter(range(64)):
            sleep(0.1)
    flags = ["".join(x) for x in itertools.permutations(real_flag)]
    flags.remove(real_flag)
    random.shuffle(flags)
    brrr_the_strings(flags)
    print("If you are so smart, then you should be able to give the flag in 15 seconds!")
    start = time()
    guess = input("> ")
    end = time()
    if guess == flag and end - start <= 15:
        print("Correct! Here is your flag: " + flag)
    else:
        print("Well, at least I can rest. GL")
        exit(0)
