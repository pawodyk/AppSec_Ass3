import os
import hashlib
from dotenv import load_dotenv
import requests
import json


load_dotenv()

VT_API_KEY = os.getenv('VT_API')

# sample_file = open('sample\cmd.exe', 'rb')
# sha1 = hashlib.sha1(sample_file.read())

# sha1 = 'ae12bb54af31227017feffd9598a6f5e'
sha1 = '7D39E928E4D6616CE1DB50D2B19C1DE703882E15'

# print('you are searching for : {}'.format(sha1.hexdigest().capitalize()))
# print('you are using : {}'.format(VT_API_KEY))


# VT_API - Get a file report: https://developers.virustotal.com/reference/file-info
url = "https://www.virustotal.com/api/v3/files/" + sha1
headers = {
   "Accept": "application/json",
   "x-apikey": VT_API_KEY
   }
response = requests.request("GET", url, headers=headers)
print(response.text)


file_out = open("notdetected.json", "w")
file_out.write(response.text)
file_out.close()

# os.startfile('output.json')

# json_resposne = response.json()


# with open('output.json') as file:
#     json_resposne = json.load(file)

    # print(type(json_resposne))
    # print(type(json_resposne['data']['attributes']['last_analysis_stats']))

    #for key in json_resposne['data']['attributes']['last_analysis_stats']:
    #    print(type(key))
    #    pass

# print(json.dumps(json_resposne['data']['attributes']['last_analysis_stats'], indent=4))

# dictionary = json_resposne['data'] #['attributes']['last_analysis_stats']
# for item in dictionary:
#     if item == 'attributes':
#         print(dictionary[item])

#for line in dictionary: print(line, dictionary[line])

# for key in json_resposne.keys():
#     if key == 'type_description':
#         print("File type: ", json_resposne[key])
#     elif key == 'meaningful_name':
#         print('file name: ', json_resposne[key])
#     print(key)


#d = dict(json_resposne)

# for k, v in d['data'].items():
#     print(k, v)




# sample_file.close()

print("\n******END******\n")