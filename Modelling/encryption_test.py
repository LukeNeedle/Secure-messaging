from encryption import *
import random
import string


print("===================================")
print("        Substitution Cipher        ")
print("===================================")
# Example usage
plainText = "Confidential information 5464446"
key = int(input("Key: "))
# The key cannot be a multiple of 62, including 0

encryptedText = substitution_encrypt(plainText, key)
print(f"Cipher Text: {encryptedText}")

decryptedText = substitution_decrypt(encryptedText, key)
print(f"Plain text: {decryptedText}")

input("Finding a bad key:")

badKeys = []

for key in range(0, 5000):
    encryptedText = substitution_encrypt(plainText, key)
    print(f"Cipher Text: {encryptedText}")

    decryptedText = substitution_decrypt(encryptedText, key)
    print(f"Plain text: {decryptedText}")
    if encryptedText == plainText:
        badKeys.append(key)

print(badKeys)

difference = []
for key in badKeys:
    if key == 0:
        difference.append(62)
    else:
        difference.append(int(key/badKeys.index(key)))

print(difference)


input("Vernam Cipher:")

print("===================================")
print("           Vernam Cipher           ")
print("===================================")
# Example usage
plainText = "Confidential information 5464446"
key = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(len(plainText)))

encryptedData = vernam_encrypt(plainText, key)
print("Encrypted data:", encryptedData)

decryptedData = vernam_decrypt(encryptedData, key)
print("Decrypted data:", decryptedData)


input("Final implementation:")

print("==================================")
print("       Final implementation       ")
print("==================================")
# Example usage
plainText = "Confidential information 5464446"
key = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(len(plainText)))

encryptedData = substitution_encrypt(vernam_encrypt(plainText, key), 55)
print("Encrypted data:", encryptedData)

decryptedData = vernam_decrypt(substitution_decrypt(encryptedData, 55), key)
print("Decrypted data:", decryptedData)