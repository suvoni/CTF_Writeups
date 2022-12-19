from src.common import *

def part2_():
    print("You are doing great! Now, let's try something harder!")
    print("I will give you AGAIN some StRiNgS, and you will have to tell me, which one is missing, seems still doable, right? :D")
    print("But I need you to hurry this time, so you will have to guess the missing string in 5 seconds.")
    print("Let's try it out!")

def part2(l):
    if (SHOULD_USE_ANNOYING_ANIMATIONS):
        for i in ChargingBar("Loading StRiNgS", max=32, check_tty=False).iter(range(32)):
            sleep(0.1)
    strings = ["".join(x) for x in itertools.product(mid_dictionary, repeat=l)]
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