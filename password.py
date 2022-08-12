import random
 
def generate_password(length):
    password = ''
    for _ in range(length):
        password += (chr(random.randint(48, 90)))
    return password