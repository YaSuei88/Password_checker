import requests
import hashlib

# take passowrds from the txt file, each passowrd should be in seperate line
with open('password.txt', mode="r", encoding='UTF-8') as my_password:
    passwords = my_password.readlines()


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f'Error fetching:{res.status_code}, check the api and try again.')
    return res


# hashes = all responses, hash_to_check = tail
def get_password_leak_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0  # return 0 if no match


def pwned_api_check(password):  # check if password exists in the API response
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_cha, tail = sha1password[:5], sha1password[5:]
    # only return the rest of the shalpssword besides frist5_cha, aka tail
    response = request_api_data(first5_cha)
    return get_password_leak_count(response, tail)


def main(passwords):
    for password in passwords:
        count = pwned_api_check(password)
        if count:
            print(
                f'{password} was found {count} times....you should change your password')
        else:
            print(f'{password} was Not found. Carry on!')
    return "checked"


main(passwords)

'''code below is for taking arguments from terminal directly
   import sys library if using the code below

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times....you should change your password')
        else:
            print(f'{password} was Not found. Carry on!' )
    return "checked"

main(sys.argv[1:])
'''
