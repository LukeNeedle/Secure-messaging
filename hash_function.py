def hash_variable(variable:str, salt:str):
    """
    Hashes the variable that has been given and applied the salt to make it harder to decode.

    Args:
        variable (str): The variable that needs hashing
        salt (str): The salt that is being applied to the variable

    Returns:
        str: The hashed variable
    """
    
    # Adds salt to the variable
    # Currently it adds the salt inbetween every other character. eg: {SALT}AB{SALT}CD{SALT}
    x = 0
    for letter in variable:
        if x == 0:
            saltedVariable = salt
            x += 1
        elif x == 1:
            saltedVariable += letter
            x += 1
        elif x == 2:
            saltedVariable += letter + salt
            x = 1
    if x == 2:
        saltedVariable += salt
    
    # Splits the salted variable into chunks with a length of 5
    chunks = []
    for i in range(0, len(saltedVariable), 5):
        if i+5 < len(saltedVariable):
            chunks.append(saltedVariable[i:i+5])
        else:
            chunks.append(saltedVariable[i:len(saltedVariable)])

    # Chunks are split into 2 parts, where every other item is in one list and the remaining are in the other list

    # Reverse the contents of the first chunk
    firstChunkFlipped = []
    for item in chunks[0::2]:
        firstChunkFlipped.append(str(item)[::-1])
    
    # Reverse the second chunk
    secondChunkReversed = []
    for i in range(len(chunks[1::2])-1, -1, -1):
        secondChunkReversed.append(chunks[1::2][i])
    
    # Piece the chunks back together
    scrambledVariableList = []
    for i in range(min(len(firstChunkFlipped), len(secondChunkReversed))):
        scrambledVariableList.append(str(firstChunkFlipped[i]) + str(secondChunkReversed[i]))

    scrambledVariableList = list(''.join(scrambledVariableList))

    saltValue = 0
    for letter in list(salt):
        saltValue += ord(letter)

    # Turn the characters into their ascii values and turn it into hex
    asciiHexCharacterList = []
    for letter in scrambledVariableList:
        asciiHexCharacterList.append(hex((ord(letter) + (len(variable) * saltValue)) * len(variable))[2:])

    return ''.join(asciiHexCharacterList)

def hash_file(file):
    """
    Hashes the file that has been given.

    Args:
        file (bytes): The variable that needs hashing

    Returns:
        bytes: The hashed file
    """

    
    return file