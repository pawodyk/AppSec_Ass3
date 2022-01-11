import os , hashlib, json, time, csv, mimetypes
from dotenv import load_dotenv
import requests, click


# set global variables
load_dotenv()
VT_API_KEY = os.getenv('VT_API')
LOG_TO_FILE = True
VERBOSE = False
WAIT_TIMER = 0
HASH_ONLY_MODE = False
VT_SCAN_TIMESTAMP = 0

LOG_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "log")
REP_DIR = os.path.dirname(os.path.realpath(__file__))

# functions

def setVTKey(input):
    global VT_API_KEY
    if isinstance(input, str):
        if len(input) == 64:
            VT_API_KEY = (input)
        ## else raise Exception
    ## else raise Exception

def getVTKey():
    global VT_API_KEY
    return VT_API_KEY

def setLogToFile(input):
    global LOG_TO_FILE
    if isinstance(input, bool):
        LOG_TO_FILE = input
    ## else raise Exception

def getLogToFile():
    global LOG_TO_FILE
    return LOG_TO_FILE

def setIsVerbose(input):
    global VERBOSE
    if isinstance(input, bool):
        VERBOSE = input
    ## else raise Exception

def getIsVerbose():
    global VERBOSE
    return VERBOSE

def setReportDirectory(input):
    global REP_DIR
    abs_input = os.path.abspath(input)
    if os.path.isdir(input):
        REP_DIR = abs_input
    else:
        REP_DIR = os.path.dirname(abs_input)

def setWaitTime(input):
    global WAIT_TIMER
    WAIT_TIMER = input

def setHashOnlyMode(input):
    global HASH_ONLY_MODE
    HASH_ONLY_MODE = input

def setVTTimeStamp():
    global VT_SCAN_TIMESTAMP
    VT_SCAN_TIMESTAMP = time.time()

def calcTimeSinceLastScan():
    global VT_SCAN_TIMESTAMP
    return time.time() - VT_SCAN_TIMESTAMP

@click.command()
@click.argument('file_path', type=click.Path(exists=True, readable=True))
@click.option('-v', '--verbose', 'isVerbose', is_flag=True,
    help="Make output more verbose")
@click.option('--log/--no_log', 'log', default=True, is_flag=True,
    help="Define if the log files for individual operations are to be created in .\\log folder")
@click.option('-r', '--report', 'report_ouput', default=REP_DIR, type=click.Path(exists=True, dir_okay=True, writable=True), 
    help="Change the location for the Report file")
@click.option('-H', '--hash_only', 'hash_only', is_flag=True,
    help="prevent software from uplaoding files to VT, the software will only check Hashes")
@click.option('-i', '--interface', is_flag=True, help = "execute user interface")
@click.option('-w', '--wait', 'wait_time', default=30, type=click.IntRange(min=0, max=600, clamp=True),
    help="define wait time between file scans in seconds")
def main(file_path, isVerbose, log, report_ouput, hash_only, interface, wait_time):
    """
    FILE_PATH defines the file or Directory to be scanned.

    ***

    This software scan the files in the provided path (directory or individual file)
    and compares the hash value on the list of known applicaions 
    on the online databases provided by http://bin-test.shadowserver.org/
    
    If the file is not defined the program will query the Virus Total API 
    to ensure the file is not a malware.

    If the file is not on the VT database the program will try to upload the file
    for analysis.
    """
    setLogToFile(log)
    setWaitTime(wait_time)
    setHashOnlyMode(hash_only)
    if isVerbose: setIsVerbose(True)
    if interface: runUserInterface()

    ## basic verification of the VT API Key
    if VT_API_KEY is None or len(VT_API_KEY) != 64:
        print("API Key not retrived from .env pelase enter manually:")
        input_API_KEY = input()
        try:
            setVTKey(input_API_KEY)
        except Exception:
            print('Incorrect VirusTotal API')
            exit()

    ## check does the user want to scan file or folder
    try:
        if os.path.isfile(file_path):
            result = analyze(file_path)
            report([result], report_ouput)
        else:
            results = scanFiles(file_path)
            report(results, report_ouput)
    except ValueError as ex_val:
        print('Incorrect Value Exception the data could not be parsed: \n',ex_val.__str__ )
    except TypeError as ex_type:
        print('Incorrect type data type, with message: ', ex_type.__str__ )
    except OSError as ex_os:
        print('OS Error occured with message: ', ex_os.strerror)
    except Exception as ex_:
        print(ex_.__str__)
    

def scanFiles(dirpath):
    os.chdir(dirpath)
    subdir = []
    files = []
    for file in os.listdir():
        path = os.path.join(os.getcwd(), file)    
        if os.path.isdir(path):
            subdir.append(path)
        elif os.path.isfile(path):
            files.append(analyze(path))
            time.sleep(1) ## just to not overwhelm the api
    for directory in subdir:
        print('\n*** lookup in', directory, '***')
        subdir_files = scanFiles(directory)
        for ent in subdir_files:
            files.append(ent)
    
    return files
    
def analyze(path):
    out = readfile(path)
    print('checking file:\t',out['name'],out['sha1'])
    file_check = checkKnownFilesDB(out['sha1'])
    if file_check is not None:
        print( out['sha1'] + " was found in " + file_check['source'])
        out['known_file_results'] = file_check
    else:
        if VERBOSE:
            print("File not in the known file database, checking in VT")
        VT_result = checkFileInVT(out['sha1'])
        if 'error' in VT_result:
            if VERBOSE:
                print('Virus Total returned fillowing error:',VT_result['error']['code'])
            if VT_result['error']['code'] == 'NotFoundError':
                if not HASH_ONLY_MODE:
                    if VERBOSE:
                        print("File not in VT database, uploading the file for analysis")
                    output_upload_file = uploadFileToVT(path) #os.path.join(out['path'],out['name'])) ## use path?
                    if 'data' in output_upload_file:
                        if output_upload_file['data']['type'] == 'analysis':
                            report_link = 'https://www.virustotal.com/gui/file/' + out['sha1']
                            print('File uploaded sucessfully to VT @ {}'.format(report_link))
                            out['VT_result'] = {'status': 'uploaded for analysis', 'link': report_link}
                else:
                    print("File not in VT database")
        else:
            
            VT_rep = 'negative' if VT_result['data']['attributes']['reputation'] < 0 else 'positive'
            VT_malicious = VT_result['data']['attributes']['last_analysis_stats']['malicious']
            report_link = 'https://www.virustotal.com/gui/file/' + out['sha1']
            print("File {0} found in VT database with reputation of {1}, and {2} vendors marked it as malicious, VT REPORT @ {3} "
                    .format(out['sha1'], VT_rep, VT_malicious, report_link))
            out['VT_result'] = VT_result
        
    # if VERBOSE:
    #     print(out)
    json_file = json.dumps(out, indent=4)
    logToFile(json_file, 'output.json')

    return out

def readfile(filepath):
    if os.path.isfile(filepath):
        out = {}
        with open(filepath, 'rb') as file:
            file_sha1 = hashlib.sha1(file.read())
            pathsplit = os.path.split(filepath)
            file_type = mimetypes.guess_type(filepath)[0] # magic.from_file(filepath, mime=True) ##not working on Linux
            # print('filename: {1}\t located at {0}\t SHA1: {2}'.format(pathsplit[0],pathsplit[1],))  # , file_sha1.hexdigest()
            out.update({'name' : pathsplit[1]})
            out.update({'path' : pathsplit[0]})
            out.update({'sha1' : file_sha1.hexdigest()})
            out.update({'type' : file_type})
            
        return out
    else:
        return None

def checkKnownFilesDB(hash):
    url = 'http://bin-test.shadowserver.org/api?sha1=' + hash
    response = requests.request("GET", url)
    response_text = response.text

    # print(len(response_text))
    if len(response_text) > 42:
        response_json = json.JSONDecoder().decode(response_text[41:])
        logToFile(response_json, "outputFileDB.json")
        
        return dict(response_json)
    else:
        return None

def checkFileInVT(hash):
    timer = calcTimeSinceLastScan()
    if timer < WAIT_TIMER:
        if VERBOSE:
            print('waiting', WAIT_TIMER - timer)
        time.sleep(WAIT_TIMER - timer)
        
    json_resposne = {}
    
    #VT_API - Get a file report: https://developers.virustotal.com/reference/file-info
    url = "https://www.virustotal.com/api/v3/files/" + hash
    headers = {
        "Accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    response = requests.request("GET", url, headers=headers)
    try:
        json_resposne = response.json()
    except Exception:
        pass

    logToFile(response.text, 'outputVT_hash.json')

    setVTTimeStamp()
    return json_resposne

def uploadFileToVT(path):
    timer = calcTimeSinceLastScan()
    if timer < WAIT_TIMER:
        if VERBOSE:
            print('waiting', WAIT_TIMER - timer)
        time.sleep(WAIT_TIMER - timer)
        

    json_resposne = {}

    url = "https://www.virustotal.com/api/v3/files"
    payload = ""
    
    with open(path, 'rb') as file:
        payload = {'file': file.read()}

    headers = {
        "x-apikey": VT_API_KEY
    }

    response = requests.request("POST", url, files=payload, headers=headers)
    try:
        json_resposne = response.json()
    except Exception:
        pass


    logToFile(response.text, "outputVT_file.json")
    
    setVTTimeStamp()
    return json_resposne

def logToFile(text, filename):
    try:
        if LOG_TO_FILE:
            text = str(text)
            file = os.path.join(LOG_DIR, filename)
            with open(file, "a") as file_out:
                file_out.write(text)
    except Exception:
        print('ERROR: Could not log to file: ' + file )

def report(data_list, out_path):
    report_path = os.path.join(out_path,'report.txt')

    known_files = []
    VT_files = []
    VT_uploaded_files = []
    error_files = []

    for file_data in data_list:
        if 'known_file_results' in file_data:
            known_files.append(file_data)

        elif 'VT_result' in file_data:
            if 'data' in file_data['VT_result']:
                VT_files.append(file_data)

            elif 'status' == 'uploaded for analysis':
                VT_uploaded_files(file_data)

        else:
            error_files.append(file_data)

    report = ["*** File scan completed " + time.asctime(time.localtime(time.time())) + '***']
    report.append("\nTotal Files scanned: " + str(len(data_list)))

    report.append("\nFiles identified in know programs database: " + str(len(known_files)))
    for entry in known_files:
        string = 'File:\t' + entry['name']
        string += ' [' + entry['sha1'] + '] ' 
        string += '\tfound @ ' + entry['path'] 
        string += '\tMIME type:' + entry['type']
        string += '\tverified using database: ' + entry['known_file_results']['source'] + '\t signed by ' + entry['known_file_results']['signer']
        report.append(string)

    report.append("\nFiles found in Virus Total database: " + str(len(VT_files)))
    for entry in VT_files:
        report_link = 'https://www.virustotal.com/gui/file/' + entry['sha1']
        times_submitted = entry['VT_result']['data']['attributes']['times_submitted']
        VT_Vote = entry['VT_result']['data']['attributes']['total_votes']
        VT_rep = 'negative' if entry['VT_result']['data']['attributes']['reputation'] < 0 else 'positive'
        VT_malicious = entry['VT_result']['data']['attributes']['last_analysis_stats']['malicious']


        string = 'File:\t' + entry['name']
        string += ' [' + entry['sha1'] + '] ' 
        string += '\tfound @ ' + entry['path'] 
        string += '\tMIME type:' + entry['type']
        string += "\n\t This file has {} reputation, and was detected as malicious by {} vendors".format(VT_rep,VT_malicious)
        string += "\n\t The VT Community voted this file: \t {} malicious / {} harmless".format(VT_Vote['malicious'], VT_Vote['harmless'])
        string += "\n\t Full VT report at " + report_link
        report.append(string)
    
    report.append("\nFiles uploaded to Virus Total for analysis: " + str(len(VT_uploaded_files)))
    for entry in VT_uploaded_files:
        string = 'File:\t' + entry['name']
        string += ' [' + entry['sha1'] + '] ' 
        string += '\tfound @ ' + entry['path'] 
        string += '\tMIME type:' + entry['type']
        string += '\tFile was uplaoded to VT for analysis, please check the VT database @ ' + entry['VT_result']['link']
        report.append(string)

    if error_files :
        report.append("\n\nFollowing files could not be processed and they will have to be manually checked")
        for entry in error_files:    
            report.append(str(entry))

    with open(report_path, 'a') as r:
        for line in report:
            r.write(line + '\n')
        r.write('\n*** END ***\n\n')
            

## I dont like spreadsheets... working code but replaced with report file writen to txt file.
# def report(out_list, path):
#     report_path = os.path.join(path,'report.csv')
#     first_row = [
#         'name', 
#         'path', 
#         'sha1', 
#         'type',
#         'In Known files database',
#         'signed by',
#         'VT Reputation',
#         'VT malicious',
#         'VT undetected',
#         'VT harmless'
#         ]

#     with open(report_path, 'w') as file:
#         csvwriter = csv.writer(file, delimiter=',',)
#         csvwriter.writerow(first_row)
#         for data in out_list:
#             data_row = [
#                 data['name'],
#                 data['path'],
#                 data['sha1'],
#                 data['type'],
#                 data['known_file_results']['source'] if 'known_file_results' in data else 'n/a',
#                 data['known_file_results']['signer'] if 'known_file_results' in data else 'n/a',
#                 data['VT_result']['data']['attributes']['reputation'] if 'VT_result' in data else 'n/a',
#                 data['VT_result']['data']['attributes']['last_analysis_stats']['malicious'] if 'VT_result' in data else 'n/a',
#                 data['VT_result']['data']['attributes']['last_analysis_stats']['undetected'] if 'VT_result' in data else 'n/a',
#                 data['VT_result']['data']['attributes']['last_analysis_stats']['harmless'] if 'VT_result' in data else 'n/a']

#             csvwriter.writerow(data_row)
#             if VERBOSE:
#                 print("writing data to file...")
#     print('report completed')
#     pass

def runUserInterface():
    print("user interface will go here!")
    exit()





if __name__ == '__main__':
    main()
