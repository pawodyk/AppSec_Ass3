import os
import hashlib
from dotenv import load_dotenv

def main():
    load_dotenv()
    VT_API_KEY = os.getenv('VT_API')    
    
    

def test():
    hash_file = open('sample\hashes.txt', 'r')
    hash_list = hash_file.readlines()
    sample_file = open('sample\sample.exe', 'rb')
    sha1 = hashlib.sha1(sample_file.read())

    print(sha1.hexdigest().capitalize())
    print(hash_list[0])

    sample_file.close()
    hash_file.close()








main()
