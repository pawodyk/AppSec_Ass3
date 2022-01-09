import os , hashlib, json, time, csv
from dotenv import load_dotenv
import requests, magic, click


# set global variables
load_dotenv()
VT_API_KEY = os.getenv('VT_API')
LOG_TO_FILE = True
VERBOSE = False
WAIT_TIMER = 0
HASH_ONLY_MODE = False

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
@click.option('-w', '--wait', 'wait_time', default=30, type=click.IntRange(min=0, max=60, clamp=True),
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
    if os.path.isfile(file_path):
        analize(file_path)
    else:
        x = scanFiles(file_path)
        report(x, report_ouput)


def scanFiles(dirpath):
    os.chdir(dirpath)
    subdir = []
    files = []
    for file in os.listdir():
        path = os.path.join(os.getcwd(), file)    
        if os.path.isdir(path):
            subdir.append(path)
        elif os.path.isfile(path):
            files.append(analize(path))
            time.sleep(1)
    for directory in subdir:
        print('\n*** lookup in', directory, '***')
        scanFiles(directory)
    
    return files
    
def analize(path):
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
                print(VT_result['error']['code'])
            if VT_result['error']['code'] == 'NotFoundError':
                if not HASH_ONLY_MODE:
                    if VERBOSE:
                        print("File not in VT database, uploading the file for analysis")
                    output_upload_file = uploadFileToVT(os.path.join(out['path'],out['name']))
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
            print("File {0} found in VT database with reputation of {1}, and {2} vendors marked it as malicious ".format(out['sha1'], VT_rep, VT_malicious))
            print('for full report see: ' + report_link)
            out['VT_result'] = VT_result
        
    if VERBOSE:
        print(out)
    json_file = json.dumps(out, indent=4)
    logToFile(json_file, 'output.json')

    return out

def readfile(filepath):
    if os.path.isfile(filepath):
        out = {}
        with open(filepath, 'rb') as file:
            file_sha1 = hashlib.sha1(file.read())
            pathsplit = os.path.split(filepath)
            file_type = magic.from_file(filepath, mime=True)
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
    
    #VT_API - Get a file report: https://developers.virustotal.com/reference/file-info
    url = "https://www.virustotal.com/api/v3/files/" + hash
    headers = {
        "Accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    response = requests.request("GET", url, headers=headers)
    json_resposne = response.json()

    logToFile(response.text, 'outputVT_hash.json')

    time.sleep(WAIT_TIMER)
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
    
    time.sleep(WAIT_TIMER)
    return response.json()


def logToFile(text, filename):
    if LOG_TO_FILE:
        text = str(text)
        file = os.path.join(LOG_DIR, filename)
        with open(file, "a") as file_out:
            file_out.write(text)

def report(out_list, path):
    report_path = os.path.join(path,'report.csv')
    first_row = [
        'name', 
        'path', 
        'sha1', 
        'type',
        'In Known files database',
        'signed by',
        'VT Reputation',
        'VT malicious',
        'VT undetected',
        'VT harmless'
        ]

    with open(report_path, 'w') as file:
        csvwriter = csv.writer(file, delimiter=',',)
        csvwriter.writerow(first_row)
        for data in out_list:
            data_row = [
                data['name'],
                data['path'],
                data['sha1'],
                data['type'],
                data['known_file_results']['source'] if 'known_file_results' in data else 'n/a',
                data['known_file_results']['signer'] if 'known_file_results' in data else 'n/a',
                data['VT_result']['data']['attributes']['reputation'] if 'VT_result' in data else 'n/a',
                data['VT_result']['data']['attributes']['last_analysis_stats']['malicious'] if 'VT_result' in data else 'n/a',
                data['VT_result']['data']['attributes']['last_analysis_stats']['undetected'] if 'VT_result' in data else 'n/a',
                data['VT_result']['data']['attributes']['last_analysis_stats']['harmless'] if 'VT_result' in data else 'n/a']

            csvwriter.writerow(data_row)
            if VERBOSE:
                print("writing data to file...")
    print('report completed')
    pass



def runUserInterface():
    print("user interface will go here!")
    exit()

if __name__ == '__main__':
    main()
