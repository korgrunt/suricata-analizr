# suricata-analizr
Analyzer of suricata output

## Install
You can create a venv, but not needed. 
The project use only ipaddress pip package which is mostely installed on all computer. 

```
pip install sys
pip install os
pip install json
pip install ipaddress
pip install datetime
pip install re
```

That's why you haven't requirements.txt in the project for pip freeze.

## Run

    For analyse file with all information you required, une option ```--all [-a]```
    ```
     python3 main.py --all <abs-path-to-pcap> <abs-path-to-yaml> <abs-path-to-rules>   
    ```
  
    For analyse file with information you required in visibility check, une option ```--visibility [-v]```
    ```
    python3 main.py -v <abs-path-to-pcap> <abs-path-to-yaml> <abs-path-to-rules> 
    ```
    
    For analyse file with information you required in visibility check, une option ```--detection [-d]```
    ```
    python3 main.py -d <abs-path-to-pcap> <abs-path-to-yaml> <abs-path-to-rules> 
    ```
    
    For read the documentation 
    ```--help [-h]```
    ```
     python3 main.py -h    
    ```
        
    For check the version 
    ```--version```
    ```
     python3 main.py --version    
    ```

## Contribute and upgrade the product

### main.py

this file contain the bootstrap of programm.
The role of main?py is to parse argument, run suricata shell commands for generate eve.json, and, in function of argument, execute detection funciton, visibility funciton, of both.

Also, he manage the print of documentation adn verson

### detection_mode.py

this file contain in the bottom of file the detection fonction which call all function corresponding to a requirement.

All function make the search in eve.jsoin and return a "report" variable
each report variable of each function are concatenate in a detection variable report and printed after all detection done. We can easily modify this for print a json formatted data, displayable in html page, which can be converted to a pdf also from the html page.

### visibility_mode.py

this file contain in the bottom of file the visibility fonction which call all function corresponding to a requirement.

All function make the search in eve.jsoin and return a "report" variable
each report variable of each function are concatenate in a visibility variable report and printed after all visibility done. We can easily modify this for print a json formatted data, displayable in html page, which can be converted to a pdf also from the html page.

### Thanks for your reading.