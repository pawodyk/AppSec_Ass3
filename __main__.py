import os
import hashlib
from dotenv import load_dotenv
import requests
import json
import time

def main():

    #print(LOG_DIR)

    scanFiles("D:\\Desktop\\Code\\MalFileDetTool\\sample") ## this will be supplied by the user.

    ### used for testing:
    # print(checkKnownFilesDB('0000004DA6391F7F5D2F7FCCF36CEBDA60C6EA02'))
    # print(checkKnownFilesDB('40ce9b61ba37022e1b3431b8ee1b37b6eb2f87ac'))

    # print(checkFileInVT('D:\\Desktop\\Code\\MalFileDetTool\\test\\cmd.exe'))
    # uploadFileToVT('D:\\Desktop\\Code\\MalFileDetTool\\test\\cmd.exe')

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


def scanFiles(dirpath):
    os.chdir(dirpath)

    subdir = []

    for file in os.listdir():
        path = os.path.join(os.getcwd(), file)
        
        if os.path.isdir(path):
            subdir.append(path)
        elif os.path.isfile(path):
            out = readfile(path)
            print('checking file:\t',out['name'],out['sha1'])
            file_check = checkKnownFilesDB(out['sha1'])
            if file_check is not None:
                out['known_file_results'] = file_check
            else:
                VT_result = checkFileInVT(out['sha1'])
                out['VT_result'] = VT_result
                time.sleep(30)

            # checkFileInVT(out['sha1'])
            # time.sleep(30)
            # uploadFileToVT(os.path.join(out['path'],out['name']))

            # print(out)

            json_file = json.dumps(out, indent=4)

            logToFile(json_file, 'output.json')

    for directory in subdir:
        print('\n*** lookup in', directory, '***')
        scanFiles(directory)
    

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

def checkKnownFilesDB(hash):
    url = 'http://bin-test.shadowserver.org/api?sha1=' + hash
    response = requests.request("GET", url)
    response_text = response.text

    # print(len(response_text))
    if len(response_text) > 42:
        response_json = json.JSONDecoder().decode(response_text[41:])
        print(response_json)

        logToFile(response.text, "outputFileDB.json")
        
        return dict(response_json)
    else:
        print("not found")
        pass

def checkFileInVT(hash):
    
    #VT_API - Get a file report: https://developers.virustotal.com/reference/file-info
    url = "https://www.virustotal.com/api/v3/files/" + hash
    headers = {
        "Accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    response = requests.request("GET", url, headers=headers)
    print(response.text)

    logToFile(response.text, 'outputVT_hash.json')

    json_resposne = response.json()

    return json_resposne


def uploadFileToVT(path):
    url = "https://www.virustotal.com/api/v3/files"

    payload = ""
    
    with open(path, 'rb') as file:
        payload = {'file': file.read()}

    headers = {
        "x-apikey": VT_API_KEY
    }


    response = requests.request("POST", url, data=payload, headers=headers)

    logToFile("uploaded to virus total:" + response.text, "outputVT_file.txt")
    
    

def logToFile(text, filename):
    file = os.path.join(LOG_DIR, filename)
    with open(file, "a") as file_out:
        file_out.write(text)

load_dotenv()
VT_API_KEY = os.getenv('VT_API')
if VT_API_KEY is None:
    print("API Key not retrived from .env pelase enter manually:")
    VT_API_KEY = input()

LOG_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "log")


main()
