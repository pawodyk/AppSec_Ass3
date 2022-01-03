import os
import hashlib
from dotenv import load_dotenv

def main():
    scan("D:\\Desktop\\Code\\MalFileDetTool\\sample")
    pass
    


def test():
    hash_file = open('sample\hashes.txt', 'r')
    hash_list = hash_file.readlines()
    sample_file = open('sample\sample.exe', 'rb')
    sha1 = hashlib.sha1(sample_file.read())

    print(sha1.hexdigest().capitalize())
    print(hash_list[0])

    sample_file.close()
    hash_file.close()


def scan(dirpath):
    os.chdir(dirpath)
    for file in os.listdir():
        filepath = os.getcwd() + '\\' + file
        out = readfile(filepath)
        print(out['name'],out['sha1'])

        

def readfile(filepath):

    out = {}
    with open(filepath, 'rb') as file:
        file_sha1 = hashlib.sha1(file.read())
        pathsplit = os.path.split(filepath)
        # print('filename: {1}\t located at {0}\t SHA1: {2}'.format(pathsplit[0],pathsplit[1],))  # , file_sha1.hexdigest()
        out.update({'name' : pathsplit[1]})
        out.update({'path' : pathsplit[0]})
        out.update({'sha1' : file_sha1.hexdigest()})

    return out


load_dotenv()

VT_API_KEY = os.getenv('VT_API')  

main()
