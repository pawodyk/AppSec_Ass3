import os
import hashlib

def main():
    hash_file = open('sample\hashes.txt', 'r')
    hash_list = hash_file.readlines()
    sample_file = open('sample\sample.exe', 'rb')
    sha1 = hashlib.sha1(sample_file.read())

    print(sha1.hexdigest().capitalize())
    print(hash_list[0])


main()
print("end")