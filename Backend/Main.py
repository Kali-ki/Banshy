from flask import Flask, request
from gevent.pywsgi import WSGIServer
import urllib.request
import typing
import os
import hashlib
import time
import logging

# Import the methods to analyse PDF and EXE files
from Analysers.PDF.PdfAnalyser import analyse_file
from Analysers.EXE.ExeAnalyser import analyze_pe
from Analysers.MICROSOFTOFFICE.MicrosoftOfficeAnalyser import analyse_microsoft_office_file

# Import the database communication
from DatabaseCommunication import DatabaseCommunication

# If True, the server will be deployed with WSGIServer instead of Flask
__PRODUCTION = True

# If __VERBOSE is True, the server will print more information
__DEBUG = True

# Logger
__LOGGER = logging.getLogger(__name__)

# Database communication
__DB = None

def get_extension(file: str) -> str:

    """
        Method to return extension of a file
        + file -> string : file name
        + return -> string : extension of the file
    """

    return file.split('.')[-1]

def download_file(url: str) -> typing.Tuple[str, str]:

    """
        Method to download a file from a given url
        + url -> string : url of the file to download
        ⮕ Return string name of the downloaded file
                        or empty string if the download failed
                        and string extension of the file
    """

    extension = get_extension(url)
    file_name = "tmp." + extension

    try:
        urllib.request.urlretrieve(url, file_name)
    except Exception as e:
        __LOGGER.error("Download failed : " + str(e))
        return "", ""
    
    return file_name, extension

def get_hash(file_path: str) -> str:

    """
        Method to get the hash of a file
        + file -> string : file name
        ⮕ Return string hash of the file
    """

    # Open the file
    with open(file_path, "rb") as f:
        # Read the content
        content = f.read()
        # Return the hash
        return hashlib.sha1(content).hexdigest()

# Flask app
app = Flask(__name__)

@app.route('/isSafe', methods=['POST'])
def url():

    """
        Method to check if a given url is safe
        Curl request to test : curl -X POST http://127.0.0.1:5000/isSafe -H 'Content-Type: application/json' -d '{"url":"https://southbend.iu.edu/students/academic-success-programs/academic-centers-for-excellence/docs/Basic%20Math%20Review%20Card.pdf"}'
    """

    if request.method == 'POST':

        # Create a new line in the log
        print("\n")

        # By default, the result is False -> not safe
        result = False
        
        # Get the url from the request
        url = request.get_json()['url']
        # Download the file
        file_name, extension = download_file(url)

        # file_name is empty if the download failed
        if file_name != "":

            __LOGGER.info("Analysing file : " + url)

            # Get the hash of the file
            hash = get_hash(file_name)
            # Check if the file is already in the database
            res = __DB.check_file(hash)

            # If the file is already in the database, return the result
            if res is not None:
                
                __LOGGER.info("File already in the database")

                if res[0] == 1:
                    result = True
                else:
                    result = False

            # If the file is not in the database, analyse it
            else:

                # Analyse the file
                if file_name != "":
                    if extension == "pdf":
                        result = analyse_file(file_name, verbose=__DEBUG)[0]
                    elif extension == "exe":
                        result = analyze_pe(file_name)
                    elif extension in ["doc", "docx", "xls", "xlsx", "ppt", "pptx"]:
                        result = analyse_microsoft_office_file(file_name)
                    
                    # Add the file to the database
                    __DB.add_file(hash, result)
            
            # Remove the file
            os.remove(file_name)

        # Return the result
        if result:
            __LOGGER.info("File is safe")
            return "url : "+str(url)+" is safe"
        else:
            __LOGGER.info("File is not safe")
            return "url : "+str(url)+" is not safe"

@app.route('/isAlive', methods=['GET'])
def is_alive():
    
        """
            Method to check if the server is alive
        """
            
        return "Server is alive"

if __name__ == '__main__':

    if __DEBUG:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    __LOGGER.info("Starting server ...")

    # Wait for the database to be ready
    time.sleep(10)

    try:
        __DB = DatabaseCommunication()

        __LOGGER.info("Server started")

        try:
            if __PRODUCTION:
                http_server = WSGIServer(('', 5000), app)
                http_server.serve_forever()
            else:
                app.run(debug=__DEBUG)
        
        except Exception as e:
            __LOGGER.critical("Server failed : " + str(e))
            __DB.close()
    
    except Exception as e:
        __LOGGER.critical("DatabaseCommunication constructor failed : " + str(e))
