"""
 6634 - Cryptography
 Name: Patrick Silver
 Date: 2/18/23
 Description: HW1 Programming Problem (Question 4) 
 Implement encryption and decryption with Simplified DES

*** EXAMPLE OF INPUT/OUTPUT ***
Plaintext (8-bit): 10111101
Key input (10-bit): 1010000010
    Sub-Keys generated (8-bit):
        K1 - 10100100
        K2 - 01000011
Ciphertext (8-bit): 01110101

With the original S1: the plaintext is 11110110 and the key is 1011110110 
With the modified Inverse S1: the plaintext is 00100101 and the key is 1100100101.
"""
KEY_LENGTH_MAX = 10
PLAINTEXT_LENGTH = 8
ONE_BIT_SHIFT = 1
TWO_BIT_SHIFT = 2

#*** Initial and expasion permutations ***
IP = (2, 6, 3, 1, 4, 8, 5, 7) #Initial Permutation
EP = (4, 1, 2, 3, 2, 3, 4, 1) #Expansion Permutation

#*** Sub key generation tables Permutations ***
P10 = (3, 5, 2, 7, 4, 10 ,1 ,9 ,8 ,6) #Permutation 10
P8 = (6, 3, 7, 4, 8, 5, 10, 9) #Permutation 8

#*** Fk function Permutations***
P4 = (2, 4, 3, 1) #Permutation 4
INV_IP = (4, 1, 3, 5, 7, 2, 8, 6) #Inverse Permutation 

#SBOX 0
S0 = [['01', '00', '11', '10'], 
      ['11', '10', '01', '00'], 
      ['00', '10', '01', '11'], 
      ['11', '01', '11', '10']]

#SBOX 1 - Stallings defined S1 box
#S1 = [['00', '01', '10', '11'], 
#      ['10', '00', '01', '11'], 
#      ['11', '00', '01', '00'], 
#      ['10', '01', '00', '11']]       


#MODIFIED SBOX - Modified S1 box for part c
S1 = [['10', '01', '00', '11'], 
 ['10', '00', '01', '11'], 
 ['11', '00', '01', '00'], 
 ['00', '01', '10', '11']]      

def permutate(text, fixed_table):
    #Function for permutating the value by the given fixed permutation table(ex: P10, P8, P4)
    outKey = ''
    text = str(text) 
    for i in fixed_table: 
        #checks the permutation table and adds values to outKey to rearrange
        #Depending on size, this will discard bits (ex: P8 will discard 2 and P4 will discard 6)
        outKey += text[i - 1] 
    return outKey 

def split(bits):
    #Returns the left and right halves of a given value; [L, R]
    return [bits[:len(bits)//2], bits[len(bits)//2:]]

def shift(key, bit_shift):
    #Shifts a given key by the specified number of bits to the left; returns new key
    outKey = ''
    for i in range(len(key)):
        #Shifts the key based off of bit_shift value
        outKey += key[(i + bit_shift) % len(key)]
    return outKey

def xor(bits1, bits2):
    #XORs the first bits by the second bits provided
    outBits = ''
    for i in range(len(bits1)):
        #Assumes that bits1 and bits2 are the same length
        outBits += str((int(bits1[i]) + int(bits2[i])) % 2)
        #Does the XOR operation and adds them to output
    return outBits

#Lookup from S0 box
def s0Lookup(text):
    #Converts binary to decimal to get r/c
    x = binary_to_decimal(text[0] + text[3])
    y = binary_to_decimal(text[1] + text[2])
    return S0[x][y]

#Lookup from S1 box
def s1Lookup(text):
    #Converts binary to decimal to get r/c
    x = binary_to_decimal(text[0] + text[3])
    y = binary_to_decimal(text[1] + text[2])
    return S1[x][y]

#Function fk, complex function that performs permutation, xor and lookup
def fk(text, key):
    text = permutate(text, EP)
    text = xor(text, key)
    text = s0Lookup(text[:4]) + s1Lookup(text[4:])
    text = permutate(text, P4)
    return text

#Function ot convert binary to decimal
def binary_to_decimal(number):
    newNum = 0
    for i in range(len(number)):
        newNum += int(number[i]) * (2 ** (len(number) - i - 1))
    return newNum

def subKey(key, subkeyNum):
    #Function to get a single subkey providing the key and the shift # provided
    #Shifting one bit is used for K1, Shifting 2 is for K2
    key = permutate(key, P10) #P10 permutation
    key = split(key) #splits P10 permutated key in [L, R]
    #Shifts both sides of the split key and joins them together. Splits depending on shift_num
    LS1_Shifted = ''.join((shift(key[0], ONE_BIT_SHIFT), shift(key[1], ONE_BIT_SHIFT))) #LS-1
    if(subkeyNum == ONE_BIT_SHIFT): 
        #K1, P8 and return key
        return permutate(LS1_Shifted, P8) #P8 permutation for K1
    elif(subkeyNum == TWO_BIT_SHIFT): 
        #K2, Split, Left shift 2 both halves, combine, and then P8 -> return
        second_split = split(LS1_Shifted) #Split after shifting LS-1 for K2
        LS2_Shift = ''.join((shift(second_split[0], TWO_BIT_SHIFT), shift(second_split[1], TWO_BIT_SHIFT))) #LS-2
        return permutate(LS2_Shift, P8) #P8 permutation for K2
    else:
        #Error; provided improper value for left bit shift
        print("ERROR: Please make sure left shift value is 1 or 2")

def generateKeys():
    #Key Generation: generate subkeys for Encryption/Decryption
    while True:
        try: #Makes sure they are giving an int value
            key_input = int(input('Enter a 10 bit key: ')) #Takes input key input from user
        except ValueError:
            #If key entered is not an int, prompt to enter again
            print("Sorry, the key must be an integer")
            continue
        else:
            #If the key entered is an int
            if len(str(key_input)) == KEY_LENGTH_MAX: #Ensures that the key entered is 10-bit
                K1 = subKey(key_input, 1) #Generates subkey 1
                K2 = subKey(key_input, 2) #Generates subkey 2
                break
            else:
                print("The key entered is not 10 bits, unable to proceed")
                continue
    return [K1, K2] #Returns subkeys 

#       *** SUB KEY GENERATION TEST CASE ***
#print("subkeys: ", generateKeys()) #Testing subkey generation (PASSED)

def plaintextPrompt():
    #Prompts User for Plaintext (in bits) with error checking
    while True:
        try: #Makes sure they are giving a number value
            key_input = int(input('Enter 8-bits of plaintext: ')) #Takes input key input from user
        except ValueError:
            #If key entered is not an int, prompt to enter again
            print("Sorry, the plaintext must be an integer, cannot convert yet")
            continue
        else:
            #If the key entered is an int and 8 bits
            if(len(str(key_input)) == PLAINTEXT_LENGTH):
                return key_input
            else:
                print("plaintext must be 8 bits, please enter again")
                continue

#Key Generation 
keys = generateKeys() #Generates subkeys (K1, K2)


#Encryption
plaintext = (input('Enter 8-bits of plaintext: '))#plaintextPrompt() #Prompts user for plaintext
input_text = permutate(plaintext, IP) #Initial permutation 
left_bits, right_bits = input_text[:4], input_text[4:] #Splits the bits
tmp = fk(right_bits, keys[0]) #Fk function 1
left_bits = xor(left_bits, tmp) #XOR against left bits original
tmp = fk(left_bits, keys[1]) #Fk function 2
right_bits = xor(right_bits, tmp) #XOR against right bits from swap

print("*** ENCRYPTION OUTPUT ***") 
print("Post SW encrytion output: ", left_bits + "   " + right_bits)
Ciphertext = permutate(right_bits + left_bits, INV_IP)
print('Cipher text output: ', Ciphertext, '\n')

#Decryption 
text_input = permutate(Ciphertext, IP) #Puts in the result ciphertext
left_bits, right_bits = text_input[:4], text_input[4:] #Splits the bits
tmp = fk(right_bits, keys[1]) #Fk function 1
left_bits = xor(left_bits, tmp) #XOR against left
tmp = fk(left_bits, keys[0]) #Fk function 2
right_bits = xor(right_bits, tmp) #XOR against right

print("*** DECRYPTION OUTPUT ***")
print("Post SW decrytion output: ", left_bits + "   " + right_bits)
plaintext = permutate(right_bits + left_bits, INV_IP)
print('Decryption Output: ', plaintext)