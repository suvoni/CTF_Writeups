import subprocess

rotors = ['I', 'II', 'III', 'IV', 'V', 'VI', 'VII', 'VIII']
rotor_positions = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
letters = ['b', 'c', 'g', 'k', 'n', 'p', 'y']

f = open('out.txt', 'w')

num_combinations = len(rotors)**3 * len(rotor_positions)**3 * len(letters)
print("Total number of combinations: " + str(num_combinations) + '\n')

count = 0

for rot1 in rotors:
    for rot2 in rotors:

        #Aenig4 does not allow repeated rotors
        if rot2 == rot1:
            continue

        for rot3 in rotors:

            #Aenig4 does not allow repeated rotors
            if rot3 == rot1 or rot3 == rot2:
                continue
                
            for pos1 in rotor_positions:
                for pos2 in rotor_positions:
                    for pos3 in rotor_positions:
                        for letter in letters:

                            count += 1
                            if count % 100000 == 0:
                                print("--> " + str(count) + "/" + str(num_combinations) + " messages decoded (" + str((float(count) / float(num_combinations))*100) + "%)...")

                        #For the given reflector/rotor/ring/plugboard configuration, attempt to decode the ciphertext
                        #in source.txt using the M4 Enigma machine
                        command = 'aenig4 -k \"b Beta ' + rot1 + ' ' + rot2 + ' ' + rot3 + ' 1 4 9 5 A' + pos1 + pos2 + pos3
                        command = command + ' W' + letter + ' XS OL DE VI JQ HU RT FA MZ\" source.txt dest.txt'
                        output = subprocess.getoutput(command)

                        #Now read the output from 'dest.txt' and write it to the culmulative output file
                        f2 = open('dest.txt', 'r')
                        decrypted = f2.readline()
                        if decrypted[0:4] == "ping":
                            f.write(decrypted)
                            print('--> Potential Answer: ' + decrypted)
                        f2.close()

f.close()
