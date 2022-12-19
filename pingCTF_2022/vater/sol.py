import subprocess

reflectors = ['b', 'c']
rotors = ['I', 'II', 'III', 'IV', 'V', 'VI', 'VII', 'VIII']
rings = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26']

f = open('out.txt', 'w')

num_combinations = len(reflectors) * len(rotors)**3 * len(rings)**2
print("Total number of combinations: " + str(num_combinations) + '\n')

count = 0

for ref in reflectors:
    for rot1 in rotors:
        for rot2 in rotors:

            #Aenig4 does not allow repeated rotors
            if rot2 == rot1:
                continue

            for rot3 in rotors:
            
                #Aenig4 does not allow repeated rotors
                if rot3 == rot1 or rot3 == rot2:
                    continue
                
                for ring3 in rings:
                    for ring4 in rings:
                        
                        count += 1
                        if count % 100000 == 0:
                            print("--> " + str(count) + " messages decoded...")

                        #For the given reflector/rotor/ring configuration, attempt to decode the ciphertext
                        #in source.txt using the M4 Enigma machine
                        command = 'aenig4 -k \"' + ref + ' Beta ' + rot1 + ' ' + rot2 + ' ' + rot3 + ' 18 14 '
                        command = command + ring3 + ' ' + ring4 + ' THGB WH AT RE YU LO KI NG FS QX CM\" source.txt dest.txt'
                        output = subprocess.getoutput(command)

                        #Now read the output from 'dest.txt' and write it to the culmulative output file
                        f2 = open('dest.txt', 'r')
                        decrypted = f2.readline()
                        f.write(decrypted)
                        f2.close()

                        if decrypted[0:4] == "ping":
                            print('--> Potential Answer: ' + decrypted)

f.close()
