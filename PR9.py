import hashlib
import itertools


def sha256(input1):
    '''
    >>> sha256('I')
    'a83dd0ccbffe39d071cc317ddf6e97f5c6b1c87af91919271f9fa140b0508c6c'
    >>> sha256('love')
    '686f746a95b6f836d7d70567c302c3f9ebb5ee0def3d1220ee9d4e9f34f5e131'
    >>> sha256('crypto')
    'da2f073e06f78938166f247273729dfe465bf7e46105c13ce7cc651047bf0ca4'
    '''
    hashed_input2 = hashlib.sha256(input1.encode('utf-8')).hexdigest()
    return hashed_input2


def authenticate(login_username, login_password):
    '''
    >>> authenticate('admin', 'admin')
    True
    >>> authenticate('admin', 'admin2')
    False
    >>> authenticate('user', 'hello')
    True
    >>> authenticate('user', 'helo')
    False
    '''
    users = {
        'admin': '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918',  # sha256('admin')
        'user': '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',  # sha256('hello')
    }
    hashed_input0 = hashlib.sha256(login_password.encode('utf-8')).hexdigest()
    if users.get(login_username) == hashed_input0:
        return True
        # SHA-256 is a cryptographic (one-way) hash function, so there is no direct way to decode it
    else:
        return False
        # That is why it is easy to first convert the password into SSH 256 and compare it.


def hack_sha256_fixed_size(passwordHash, length):
    '''
    >>> hack_sha256_fixed_size('8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918',5)
    'admin'
    >>> hack_sha256_fixed_size('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',5)
    'hello'
    >>> hack_sha256_fixed_size('a819d7cd38e9101be2e496298e8bf426ce9cdf78d2af35ddf44c6ad25d50158b',5)
    'crypt'
    >>> hack_sha256_fixed_size('688787d8ff144c502c7f5cffaafe2cc588d86079f9de88304c26b0cb99ce91c6',3)
    'asd'
    >>> hack_sha256_fixed_size('7ec658e98073955c48314d0146593497a163d79f4e1dfea4bab03b79af227214',4)
    'elte'
    '''
    char1 = "abcdefghijklmnopqrstuvwxyz"
    y = ''
    hashtype = 'sha256'
    wordlistHash = ''
    passwordHash = passwordHash

    while wordlistHash != passwordHash:
        for c in itertools.product(char1, repeat=length):
            word = y.join(c)
            if hashtype == 'sha256':
                wordlistHash = hashlib.sha256(word.encode("utf-8")).hexdigest()
                if wordlistHash == passwordHash:
                    return f'{word}'
        else:
            return None


def hack_sha256(passwordHash):
    '''
    >>> hack_sha256('8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918')
    'admin'
    >>> hack_sha256('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824')
    'hello'
    >>> hack_sha256('a819d7cd38e9101be2e496298e8bf426ce9cdf78d2af35ddf44c6ad25d50158b')
    'crypt'
    >>> hack_sha256('688787d8ff144c502c7f5cffaafe2cc588d86079f9de88304c26b0cb99ce91c6')
    'asd'
    >>> hack_sha256('7ec658e98073955c48314d0146593497a163d79f4e1dfea4bab03b79af227214')
    'elte'
    '''

    char1 = "abcdefghijklmnopqrstuvwxyz"
    y = ''
    length = 1
    hashtype = 'sha256'
    wordlistHash = ''
    passwordHash = passwordHash

    for i in range(10):
        while wordlistHash != passwordHash:
            for c in itertools.product(char1, repeat=length):
                word = y.join(c)
                if hashtype == 'sha256':
                    wordlistHash = hashlib.sha256(word.encode("utf-8")).hexdigest()
                    if wordlistHash == passwordHash:
                        return f'{word}'
            else:
                length += 1


# def Longer_example():
#     x = "e06554818e902b4ba339f066967c0000da3fcda4fd7eb4ef89c124fa78bda419"
#     path = r"C:\all_e_word.txt"
#     path1 = r"C:\common_pass.txt"
#     path2 = r"C:\list_of_all_movies.txt"
#
'''We know that we connot use brute force it takes very long run, So, creating a Ranbow Table to compare the
hash 256 or similar , Now I downlaod first all english word and call the file in the function and compare the
provided hashes'''
#
#     # for Above Ranbow Table I Hacked 2 hashes. all_e_word.txt
#     with open(path, encoding="utf-8") as f:
#         lines = [line.rstrip('\n') for line in f]
#         for i in lines:
#             hashed_input0 = hashlib.sha256(i.encode('utf-8')).hexdigest()
#             if hashed_input0 == x:
#                 return hashed_input0, i
#
"I FOUND (1 , 3) HASH 256"
''' e06554818e902b4ba339f066967c0000da3fcda4fd7eb4ef89c124fa78bda419 cryptography '''
''' f2b826b18b9de86628dd9b798f3cb6cfd582fb7cee4ea68489387c0b19dc09c1 vulnerable '''
#
'''Search the remaining hash in most common password'''  # common_pass.txt

#         with open(path1, encoding="utf-8") as f1:
#             lines1 = [line0.rstrip('\n') for line0 in f1]
#             for a in lines1:
#                 hashed_input1 = hashlib.sha256(i.encode('utf-8')).hexdigest()
#                 if hashed_input1 == x:
#                     return hashed_input1, a
''' The ranbow table which has most common 10000 password,  didnt find the remaining hash. '''
#
''' I downloded different ranbow tables txt file in my desktop : e.g list of actress names, popular places in the
world, famous personalities, list of cars name, list of countries, and cities.
finally I downloaded list of all movies'''

'''then drop all the list in my code just add 3 paths to short the code'''  # list_of_all_movies.txt
#         with open(path2, encoding="utf8") as f2:
#             lines2 = [line1.rstrip('\n') for line1 in f2]
#             for b in lines2:
#                 hashed_input2 = hashlib.sha256(b.encode('utf-8')).hexdigest()
#                 if hashed_input2 == x:
#                     return hashed_input2, b
#
"I FOUND 2 HASH 256 (2)"
'''8aa261cbc05ad6a49bea91521e51c8b979aa78215b8defd51fc0cebecc4d5c96 romeo and juliet'''
#
#
''' ALL HASHES
e06554818e902b4ba339f066967c0000da3fcda4fd7eb4ef89c124fa78bda419 cryptography
# 
8aa261cbc05ad6a49bea91521e51c8b979aa78215b8defd51fc0cebecc4d5c96 romeo and juliet

f2b826b18b9de86628dd9b798f3cb6cfd582fb7cee4ea68489387c0b19dc09c1 vulnerable 
'''
#
# Longer_example()


def authenticate_with_pepper(login_username, login_password):
    '''
    >>> authenticate_with_pepper('admin','admin')
    True
    >>> authenticate_with_pepper('admin','admin2')
    False
    >>> authenticate_with_pepper('user','hello')
    True
    >>> authenticate_with_pepper('user','helo')
    False
    '''
    users_with_pepper = {
        'admin': {'passwordHash': '89e6b5ed137e3864d99ec9b421cf6f565d611f4c2b98e31a7d353d63aa748e9c'},
        # sha256('this_can_help_to_confuse_the_attacker_admin')
        'user': {'passwordHash': '6dc765830e675d5fa4a9afb248be09a0407f6353d44652fd9b36038884a76323'},
        # sha256('this_can_help_to_confuse_the_attacker_hello')
    }
    pepper_prefix = 'this_can_help_to_confuse_the_attacker_'
    login_password_pepper = pepper_prefix + login_password
    hashed_input1 = hashlib.sha256(login_password_pepper.encode('utf-8')).hexdigest()
    if users_with_pepper.get(login_username).get('passwordHash') == hashed_input1:
        return True
    else:
        return False


def authenticate_with_pepper_and_salt(login_username, login_password):
    '''
    >>> authenticate_with_pepper_and_salt('admin', 'admin')
    True
    >>> authenticate_with_pepper_and_salt('admin', 'admin2')
    False
    >>> authenticate_with_pepper_and_salt('user', 'hello')
    True
    >>> authenticate_with_pepper_and_salt('user', 'helo')
    False
    '''
    users_with_pepper_and_salt = {
        'admin': {'passwordHash': 'd3eab7f4d6974f1db32b9cd9923fce9b434b28dc229b6582b845f1fca770d9f7',
                  'salt': "5294976873732394418"},
        # sha256('this_can_help_to_confuse_the_attacker_admin5294976873732394418')
        'user': {'passwordHash': '976c73e0b408c89df3c1a12c3b0c45a6fee71bc1de5b47a88fae1a5e69ba6e28',
                 'salt': '1103733363818826232'},
        # sha256('this_can_help_to_confuse_the_attacker_hello1103733363818826232')
    }
    salt_value = users_with_pepper_and_salt.get(login_username).get('salt')
    pepper_prefix = 'this_can_help_to_confuse_the_attacker_'
    login_password_pepper = pepper_prefix + login_password + salt_value
    hashed_input1 = hashlib.sha256(login_password_pepper.encode('utf-8')).hexdigest()
    if users_with_pepper_and_salt.get(login_username).get('passwordHash') == hashed_input1:
        return True
    else:
        return False
