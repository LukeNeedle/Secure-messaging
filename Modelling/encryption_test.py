from encryption import encrypt, decrypt

# Example usage
plainText = "Confidential information 5464446"
key = input("Key: ")
# The key cannot be a multiple of 62, including 0

encryptedText = encrypt(plainText, key)
print(f"Cipher Text: {encryptedText}")

decryptedText = decrypt(encryptedText, key)
print(f"Plain text: {decryptedText}")

input("Finding a bad key:")

badKeys = []

for key in range(0, 5000):
    encryptedText = encrypt(plainText, key)
    print(f"Cipher Text: {encryptedText}")

    decryptedText = decrypt(encryptedText, key)
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