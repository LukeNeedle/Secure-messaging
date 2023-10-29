import string

def encrypt(plainText:str, key:int):
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

