"""
 6634 - Cryptography
 Name: Patrick Silver
 Date: 3/26/23
 Description: HW2 Programming Problem (Question 6) 
 Two different attacks on RSA that also displays the run time of each
 Attack 1: Generates all possible values of M till it finds one for which Me = C mod n. Here the output should consist of M.
 Attack 2: Factors n to recover the primes p, q such that n = pq. Calculates the private key d, n, and then calculate M = Cd mod n. 
           using d from e and Φ(n), and for modular exponentiation. Here the output should consist of p, q, d,M.

Both attacks run on three different example inputs:
a) e = 3, n = 15, C = 8
b) e = 13, n = 527, C = 152
c) User input prompted for; e, n, and C
"""
import time

#*** Attack 1: Brute Force ***
def bruteForceAttack(e, n, c):
    start_time = time.perf_counter() # Start the timer
    
    #Try all possible values of M until it finds one where Me = C mod n
    for m in range(n):
        if pow(m, e, n) == c:
            #Found the correct M, stop searching and return it with time
            end_time = time.perf_counter()
            return m, end_time - start_time
    
    #If we didn't find a valid M, return None with time
    end_time = time.perf_counter() #End the timer
    return None, end_time - start_time

#*** Attack 2: Factoring ***
def factoringAttack(e, n, c):
    #Factoring equations are taken from "Cryptography and network security principles and practice" by William Stallings
    start_time = time.perf_counter() #Start the timer
    
    #Factor n to obtain the primes p and q
    for i in range(2, n):
        if n % i == 0:
            p = i
            q = n // i
            break

    #Calculate phi(n)
    phi = (p - 1) * (q - 1)
    
    #Calculate the private key d
    for d in range(1, phi):
        if (d * e) % phi == 1:
            break
    
    #Decrypt the ciphertext to obtain the plaintext
    m = pow(c, d, n)
    
    #Stop the timer and return the results and time
    end_time = time.perf_counter() #End the timer
    return p, q, d, m, end_time - start_time


#***************OUTPUT******************
#Example (a) Output
e = 3
n = 15
c = 8
m1, attack_time1 = bruteForceAttack(e, n, c)
p1, q1, d1, m2, attack_time2 = factoringAttack(e, n, c)

print(f"Example (a): ")
print(f"\nBrute Force Attack:\nM = {m1}\nTime = {attack_time1:.6f} seconds\n")
print("Factoring Attack: ")
print(f"P = {p1}\nQ = {q1}\nD = {d1}\nM = {m2}\nTime = {attack_time2:.6f} seconds\n")

#Example (b) Output
e = 13
n = 527
c = 152
m1, attack_time1 = bruteForceAttack(e, n, c)
p1, q1, d1, m2, attack_time2 = factoringAttack(e, n, c)

print("Example (b):\nBrute Force Attack: ")
print(f"M = {m1}\nTime = {attack_time1:.6f} seconds\n")
print("Factoring Attack: ")
print(f"P = {p1}\nQ = {q1}\nD = {d1}\nM = {m2}\nTime = {attack_time2:.6f} seconds\n")

#Example (c) Output
print("Example (c): ") #Prompts user for variable input
#Tested and confirmed it can handle numbers that are about 6 digits on my machine
e = int(input("Enter e: "))
n = int(input("Enter n: "))
c = int(input("Enter C: "))
m1, attack_time1 = bruteForceAttack(e, n, c)
p1, q1, d1, m2, attack_time2 = factoringAttack(e, n, c)

print("\nBrute Force Attack: ")
print(f"M = {m1}\nTime = {attack_time1:.6f} seconds\n")
print("Factoring Attack: " )
print(f"P = {p1}\nQ = {q1}\nD = {d1}\nM = {m2}\nTime = {attack_time2:.6f} seconds\n")
