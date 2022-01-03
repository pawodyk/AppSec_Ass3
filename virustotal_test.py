import os
import hashlib
from dotenv import load_dotenv
import requests
import json


load_dotenv()

VT_API_KEY = os.getenv('VT_API')

sample_file = open('sample\cmd.exe', 'rb')
sha1 = hashlib.sha1(sample_file.read())

print('you are searching for : {}'.format(sha1.hexdigest().capitalize()))
print('you are using : {}'.format(VT_API_KEY))


# VT_API - Get a file report: https://developers.virustotal.com/reference/file-info
url = "https://www.virustotal.com/api/v3/files/" + sha1.hexdigest()
headers = {
    "Accept": "application/json",
    "x-apikey": VT_API_KEY
    }
response = requests.request("GET", url, headers=headers)
#print(response.text)


file_out = open("output.txt", "w")
file_out.write(response.text)
file_out.close()

os.startfile('output.txt')


sample_file.close()

print("end")