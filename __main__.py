import os , hashlib, json, time
from dotenv import load_dotenv
import requests, magic, click


# set global variables
load_dotenv()
VT_API_KEY = os.getenv('VT_API')
LOG_TO_FILE = True
VERBOSE = False

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

@click.command()
@click.argument('file_path', type=click.Path(exists=True, readable=True))
@click.option('-v', '--verbose', 'isVerbose', is_flag=True,
    help="Make output more verbose")
@click.option('--log/--no_log', 'Log', default=True, is_flag=True,
    help="Define if the log files for individual operations are to be created in .\\log folder")
@click.option('-r', '--report', 'report_ouput', default=REP_DIR, type=click.Path(exists=True, dir_okay=True, writable=True), 
    help="Change the location for the Report file")
@click.option('-H', '--hash_only', 'hash_only', is_flag=True,
    help="prevent software from uplaoding files to VT, the software will only check Hashes")
@click.option('-i', '--interface', is_flag=True, help = "execute user interface")
@click.option('-w', '--wait', 'wait_time', default=1, type=click.IntRange(min=0, max=60, clamp=True),
    help="define wait time between file scans in seconds")
def main(file_path, isVerbose, Log, report_ouput, hash_only, interface, wait_time):
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

    setLogToFile(Log)

    if isVerbose: setIsVerbose(True)
    if interface: runUserInterface()
    

    # print(file_path, isVerbose, noLog, report_ouput, hash_only)

    # print(LOG_TO_FILE, VERBOSE, LOG_DIR, REP_DIR)


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
        scanFiles(file_path)


    # print("This is the application to scan files using list of known programs and VirusTotal")

    # path_to_scan = input("Please enter the full path to the folder you would like to scan:")
    # scanFiles(file_path)


    # scanFiles("D:\\Desktop\\Code\\MalFileDetTool") ## this will be supplied by the user.

    ### used for testing:
    # print(checkKnownFilesDB('0000004DA6391F7F5D2F7FCCF36CEBDA60C6EA02'))
    # print(checkKnownFilesDB('40ce9b61ba37022e1b3431b8ee1b37b6eb2f87ac'))

    # print(checkFileInVT('D:\\Desktop\\Code\\MalFileDetTool\\test\\cmd.exe'))
    # uploadFileToVT('D:\\Desktop\\Code\\MalFileDetTool\\test\\cmd.exe')

    pass


def scanFiles(dirpath):
    os.chdir(dirpath)
    subdir = []
    for file in os.listdir():
        path = os.path.join(os.getcwd(), file)    
        if os.path.isdir(path):
            subdir.append(path)
        elif os.path.isfile(path):
            analize(path)
            time.sleep(1)
    for directory in subdir:
        print('\n*** lookup in', directory, '***')
        scanFiles(directory)
    
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
                if VERBOSE:
                    print("File not in VT database, uploading the file for analysis")
                output_upload_file = uploadFileToVT(os.path.join(out['path'],out['name']))
                if 'data' in output_upload_file:
                    if output_upload_file['data']['type'] == 'analysis':
                        print('File uploaded sucessfully to VT')
                        out['VT_result'] = {'status': 'uploaded for analysis', 'link': 'https://www.virustotal.com/api/v3/files/' + out['sha1']}
        else:
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
        # logToFile(response_json, "outputFileDB.json")

        print(response_json)
        
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

    time.sleep(30)
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
    
    time.sleep(30)
    return response.json()


def logToFile(text, filename):
    if LOG_TO_FILE:
        text = str(text)
        file = os.path.join(LOG_DIR, filename)
        with open(file, "a") as file_out:
            file_out.write(text)

def report(out):
    pass

def runUserInterface():
    print("user interface will go here!")
    exit()

if __name__ == '__main__':
    main()
