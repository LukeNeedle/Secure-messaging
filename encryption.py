import string

def substitution_encrypt(plainText:str, key:int):
    """
    Implements a substitution cipher to encrypt the text passed in.

    Args:
        plainText (str): The plain text to be encrypted.
        key (int): The key to encrypt the string by.

    Returns:
        str: The encrypted string.
    """

    characters = string.ascii_letters + string.digits
    map = {}
    
    for index in range(len(characters)):
        map[characters[index]] = characters[(index+key)%len(characters)]
    
    cipherText = []
    
    for character in plainText:
        if character in characters:
            temp = map[character]
            cipherText.append(temp)
        else:
            temp = character
            cipherText.append(temp)
    
    cipherText = ''.join(cipherText)
    return cipherText

def substitution_decrypt(encryptedText:str, key:int):
    """
    Implements a substitution cipher to decrypt the text passed in.

    Args:
        encryptedText (str): The encrypted text to be decrypted.
        key (int): The key to decrypt the string by.

    Returns:
        str: The decrypted string.
    """
    characters = string.ascii_letters + string.digits
    map = {}

    for index in range(len(characters)):
        map[characters[index]] = characters[(index-key)%(len(characters))]
    
    decryptedText = []
    
    for char in encryptedText:
        if char in characters:
            temp = map[char]
            decryptedText.append(temp)
        else:
            temp = char
            decryptedText.append(temp)
    
    decryptedText = ''.join(decryptedText)
    return decryptedText

def vernam_encrypt(plainText, key):
    cipherText = ""
    for i in range(len(plainText)):
        print(f"{plainText[i]} ^ {key[i]} = {ord(plainText[i]) ^ ord(key[i])}")
        cipherText += chr(ord(plainText[i]) ^ ord(key[i]))
    return cipherText


def vernam_decrypt(cipherText, key):
    plainText = ""
    for i in range(len(cipherText)):
        plainText += chr(ord(cipherText[i]) ^ ord(key[i]))
    return plainText

def encrypt(plainText:str, vernamKey:str, subsitutionKey:int):
    """
    Encrypts the plain text using the keys provided.

    Args:
        plainText (str): The text to be encrypted.
        vernamKey (str): The key for vernam encrpytion.
        subsitutionKey (int): The key for substitution cipher.

    Returns:
        str: The encrypted plainText.
    """
    return vernam_encrypt(substitution_encrypt(plainText, subsitutionKey), vernamKey)

def decrypt(cipherText:str, vernamKey:str, subsitutionKey:int):
    """
    Decrypts the encrypted text using the keys provided.

    Args:
        cipherText (str): The text to be decrypted.
        vernamKey (str): The key for vernam encrpytion.
        subsitutionKey (int): The key for substitution cipher.

    Returns:
        str: The plain text.
    """
    return substitution_decrypt(vernam_decrypt(cipherText, vernamKey), subsitutionKey)