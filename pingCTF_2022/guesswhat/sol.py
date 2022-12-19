import pexpect
from src.common import *
import hashlib
import time
import secrets

flag_chars = "F28ied9a4n"
flags = ["".join(x) for x in itertools.permutations(flag_chars)]
print("Number of flags = " + str(len(flags)) + "\n")

print("--> Running Exploit Script for pingCTF Challenge \"Guess What\"...")

con = pexpect.spawn('nc guess_what.ctf.knping.pl 20000', timeout=30)
response = con.expect( ["sha256", pexpect.TIMEOUT, pexpect.EOF] )
if response == 1:
    print("----> Exploit Result: Failure (Netcat connection timed out)")
    exit()
elif response == 2:
    print("----> Exploit Result: Failure (Netcat response different than expected response)")
    exit()

line0 = con.readline().decode()

#For the initial test
rest = None
prefix = line0[2:36]
c = line0[52:116]

print("\nFinding the 3-byte secret value 'rest'...\n")

for i in range(0, 16777216):
    rest = "{:06x}".format(i)
    if hashlib.sha256((prefix + rest).encode()).hexdigest() == c:
        print("--> Sending: " + rest + "\n")
        break

con.sendline(rest)
response = con.expect(["Hi, this is my game", pexpect.TIMEOUT, pexpect.EOF])
if response == 1:
    print("----> Exploit Result: Failure (Netcat connection timed out)")
    exit()
elif response == 2:
    print("----> Exploit Result: Failure (Netcat response different than expected response)")
    exit()

line = con.readline().decode()
print(line, end="")
line = con.readline().decode()
print(line, end="")
line = con.readline().decode()
print(line, end="")

#Part 1 begins now
con.sendline()

for i in range(2, 18):
 
    strings = ["".join(x) for x in itertools.product(intro_dictionary, repeat=i)]
    print("Iteration " + str(i) + ":")

    response = con.expect(["PRINTING...", pexpect.TIMEOUT, pexpect.EOF])
    if response == 1:
        print("----> Exploit Result: Failure (Netcat connection timed out)")
        exit()
    elif response == 2:
        print("----> Exploit Result: Failure (Netcat response different than expected response)")
        exit()

    line = con.readline().decode()

    num_reads = 2**i - 1
    remaining_strings = []
    for j in range(0, num_reads):
        line = con.readline().decode()[0:i]
        strings.remove(line)
   
    line = con.readline().decode()
    line = con.readline().decode()

    print("--> Sending: " + strings[0] + "\n")
    con.sendline(strings[0])
   
line = con.readline().decode()
print(line, end="")
line = con.readline().decode()
print(line, end="")
line = con.readline().decode()
print(line, end="")
line = con.readline().decode()
print(line, end="")
line = con.readline().decode()
print(line, end="")
line = con.readline().decode()
print(line)

#Part 2 begins here
con.sendline()
for i in range(2, 6):
 
    strings = ["".join(x) for x in itertools.product(mid_dictionary, repeat=6)]
    print("Iteration " + str(i) + ":")

    response = con.expect(["PRINTING...", pexpect.TIMEOUT, pexpect.EOF])
    if response == 1:
        print("----> Exploit Result: Failure (Netcat connection timed out)")
        exit()
    elif response == 2:
        print("----> Exploit Result: Failure (Netcat response different than expected response)")
        exit()

    line = con.readline().decode()

    num_reads = 4**6 - 1
    remaining_strings = []
    for j in range(0, num_reads):
        line = con.readline().decode()
        strings.remove(line[0:6])
   
    line = con.readline().decode()
    line = con.readline().decode()

    print("--> Sending: " + strings[0] + "\n")
    con.sendline(strings[0])
   
#Part 3!!
line = con.readline().decode()
print("Line 1: " + line, end="")
line = con.readline().decode()
print("Line 2: " + line, end="")
line = con.readline().decode()
print("Line 3: " + line, end="")

con.sendline()

response = con.expect(["PRINTING...", pexpect.TIMEOUT, pexpect.EOF])
if response == 1:
    print("----> Exploit Result: Failure (Netcat connection timed out)")
    exit()
elif response == 2:
    print("----> Exploit Result: Failure (Netcat response different than expected response)")
    exit()

flags2 = []
line = con.readline().decode().rstrip()
i = 1
while "DONE PRINTING" not in line:
    #if line in flags:
    print(i)
    flags2.append(line)
    #flags.remove(line)
    #else:
    #    print("Could not find " + line + " in flags.")
    #    print("line length = " + str(len(line)))
    line = con.readline().decode().rstrip()
    i += 1
print("--> Finished with the processing!")
print("--> Final flags list size: " + str(len(flags)))
print("--> Final flags2 list size: " + str(len(flags2)))
f = list(set(flags) - set(flags2))
print(f)
final_flag = "ping{" + flags[0] + "}"
print("--> Sending: " + final_flag)

line = con.readline().decode()
print(line, end="")
line = con.readline().decode()
print(line, end="")
line = con.readline().decode()
print(line, end="")
line = con.readline().decode()
print(line, end="")
line = con.readline().decode()
print(line)


con.close()


exit()
