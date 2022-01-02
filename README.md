# Application Security - Assignment 3

## Requirements
You are required to develop an application and write a report on what code you used (libraries, how the functions work etc.) and then also you must document some use case examples to illustrate how the application works. You can use screenshots to support your use cases. Your code should be user friendly and include any necessary exception handling so that the program does not crash if the user enters an incorrect input.
In each of the 4 options below, the fully working, fully implemented code is worth 40% and the report is worth 10%.

### Code Specifications
#### Malicious file detection tool (hashing)
File identification and malicious code detection are important parts of an investigation. The idea of this application is to scan a file system and identify benign or malicious files. In order to rule out the benign files, you should use a look up database, such as NIST NSRL. The remaining files should be uploaded to VirusTotal (VT) via the API and checked. I would suggest you use a virtual machine as your test environment, so that you can add some malicious files to the system to show the reports returned from VT.

#### Functions “could” include:
- Menu()
- Scanfilesystem() - function to walk through the file system and parse the files. All files should be hashed using a suitable hash (e.g., MD% or SHA).
- Queryhashedb() - this function will do a lookup of the hashes on a benign DB and if the hash is found, it is discarded from the list.
- Queryvt() - this function will query the remaining file hashes against the VT repository.
- Report() - this function will write a report to a file of the malicious files found on the system.

### Project Deliverables
- Fully implemented code: The code must be fully working or at least runnable for the parts you did get working. I cannot grade your application if I cannot execute it. Note that you must clearly indicate any external modules/ libraries you have used in your code, so that I can also import them to run the code. Your code should be easily readable and promote good coding practice (descriptive comments, code reuse, good formatting etc.)
- Report: As stated above, the report should document the development of your application (what it does, how it works, libraries used etc.) and a walk-through of some example cases to show it in action (using screenshots to illustrate the outputs). 

### Deadline:
Code and report should be zipped and uploaded to Moodle before 11:59pm on 10th January
2022.


## Deployment

create virtual enviroment: ```python -m venv venv_MalFileSetTool```

run virtual enviroment: ```.\venv_MalFileSetTool\Scripts\activate```

install python requirements for this project: ```pip3 install -r requirements.txt```

## code