from src.common import *

def part1_():
    print("Hi, this is my game :)")
    print("I will give you some sTrInGs, and you will have to tell me, which one is missing, seems easy, right? :D")
    print("Let's try it out!")

def part1(l):
    if (SHOULD_USE_ANNOYING_ANIMATIONS):
        for i in ChargingBar("Loading sTrInGs", max=16, check_tty=False).iter(range(16)):
            sleep(0.1)
    strings = ["".join(x)
               for x in itertools.product(intro_dictionary, repeat=l)]
    print(strings)
    indexToRemove = bytes_to_long(os.urandom(32)) % len(strings)
    removedString = strings[indexToRemove]
    strings.remove(removedString)
    random.shuffle(strings)
    brrr_the_strings(strings)
    print("Which one is missing?")
    guess = input("> ")
    if guess == removedString:
        print("Correct!")
    else:
        print("Wrong!!!!! Cmon, you can do it!")
        exit(0)
