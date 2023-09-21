def hash_variable(variable:str, salt:str):
    """
    Hashes the variable that has been given and applied the salt to make it harder to decode.

    Args:
        variable (str): The variable that needs hashing
        salt (str): The salt that is being applied to the variable

    Returns:
        bytes: The hashed variable
    """
    
    saltedVariable = salt
    
    for letter in variable:
        saltedVariable += letter + salt

    saltedVariable = bytes(saltedVariable)
    
    import hashlib
    hashedVariable = hashlib.sha3_512(saltedVariable).hexdigest()
    
    return hashedVariable

def hash_file(file):
    """
    Hashes the file that has been given.

    Args:
        file (bytes): The variable that needs hashing

    Returns:
        bytes: The hashed file
    """

    
    return file