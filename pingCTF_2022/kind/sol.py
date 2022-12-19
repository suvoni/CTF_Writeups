import subprocess

reflectors = ['b', 'c']
rotors = ['I', 'II', 'III', 'IV', 'V', 'VI', 'VII', 'VIII']

f = open('out.txt', 'w')
t = None

for ref in reflectors:
    for rot2 in rotors:
        for rot3 in rotors:

            #Aenig4 does not allow repeated rotors
            if rot2 == rot3:
                continue

            if ref == 'b':
                t = 'Beta'
            else:
                t = 'Gamma'

            #For the given reflector/rotor/ring configuration, attempt to decode the ciphertext
            #in source.txt using the M4 Enigma machine
            command = 'aenig4 -k \"' + ref + ' ' + t + ' III ' + rot2 + ' ' + rot3 + ' 1 10 6 9 '
            command = command + 'AGOL GI VE TO YB AC KP LZ XR QH FN\" source.txt dest.txt'
            output = subprocess.getoutput(command)

            #Now read the output from 'dest.txt' and write it to the culmulative output file
            f2 = open('dest.txt', 'r')
            decrypted = f2.readline()
            f.write(decrypted)
            f2.close()

            if(decrypted[0:4] == 'ping'):
                print('--> Potential Answer: ' + decrypted)

f.close()
