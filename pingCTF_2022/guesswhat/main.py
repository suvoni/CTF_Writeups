from src.common import *
from src.pow import NcPowser
from src.part1 import part1_, part1
from src.part2 import part2_, part2
from src.part3 import part3_, part3

def main():
    part1_()
    input("Press enter to continue...")
    for i in range(2, 18):
        part1(i)
    part2_()
    input("Press enter to continue...")
    for i in range(2, 6):
        part2(6)
    part3_()
    input("Press enter to continue...")
    part3()

if __name__ == '__main__':
    if (SHOULD_USE_POW):
        nc = NcPowser()
        if nc.pow():
            main()
        else:
            print("Wrong answer")
            exit(0)
    else:
        main()
