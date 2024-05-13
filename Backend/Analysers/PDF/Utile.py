import os
import typing
import re
import pandas as pd
from subprocess import Popen, PIPE
import logging

# Logger
__LOGGER = logging.getLogger(__name__)

def execute_command(list_args: list[str]) -> typing.Tuple[bool, list[str]]:

    """
        Execute a command
        + list_args -> list of arguments for the command
        
        ⮕ Return True if the command worked, False otherwise. And the lines of the output
    """

    process = Popen(list_args, stdout=PIPE, stderr=PIPE)
    lines, stderr = process.communicate()

    stderr = stderr.decode("utf-8").split("\n")

    if stderr != ['']:
        __LOGGER.error("execute_command() -> " +str(stderr))
        return False, ""

    lines = lines.decode("utf-8").split("\n")

    return True, lines

def shapped_dict(dict_pdfid: dict, dict_pdf_parser: dict) -> pd.DataFrame:

    """
        Create a dataframe from the dictionaries
        + dict_pdfid -> dictionary from the pdfid command
        + dict_pdf_parser -> dictionary from the pdf_parser command

        ⮕ Return the dataframe
    """
    
    # Create a empty dictionary
    dict = {}
    # List of keywords to search for in the PDF
    keys = ['isAValidPDF', 'header', 'obj', 'endobj', 'stream', 'endstream', 'xref', 'trailer', 'startxref', 'Page', 'Encrypt', 'ObjStm', 'JS', 'JavaScript', 'AA', 'OpenAction', 'AcroForm', 'JBIG2Decode', 'RichMedia', 'Launch', 'EmbeddedFile', 'XFA', 'Colors', 'URI']
    
    # Initialize the dictionary with 0
    for key in keys: dict[key] = 0

    # Add the values from the pdfid and pdf_parser dictionaries
    if dict_pdfid['isAValidPDF']:
        dict['isAValidPDF'] = 1
        for keyword in keys[1:-1]: dict[keyword] = dict_pdfid[keyword]
    else: dict['isAValidPDF'] = 0

    # Add the values from the pdf_parser dictionary
    for keyword in ["URI", "JS", "JavaScript", "AA", "OpenAction", "Launch", "AcroForm"]:
        dict[keyword] = len(dict_pdf_parser[keyword])

    if 'header' in dict_pdfid:
        # Regex to find version (x.x), then set header with it
        pattern = r'\b\d\.\d\b'
        matches = re.findall(pattern, dict['header'])
        # Keep last digit of version
        dict['header'] = int(matches[0][-1])

    # Convert the dictionary to a dataframe
    df = pd.DataFrame.from_dict([dict])

    # Rename the column header to pdf_version
    df.rename(columns={'header': 'pdf_version'}, inplace=True)

    return df

def keep_only_numbers(string: str) -> str:

    """
        Keep only the numbers in a string
        + string -> the string to clean

        ⮕ Return the string with only the numbers
    """

    return ''.join(filter(str.isdigit, string))

def is_folder_exist(folder_path: str) -> bool:

    """
        Check if a folder exists
        + folder_path -> path to the folder

        ⮕ Return True if the folder exists, False otherwise
    """

    if not os.path.exists(folder_path):
        __LOGGER.error("Folder path does not exist. Exiting...")
        return False

    if not os.path.isdir(folder_path):
        __LOGGER.error("Folder path does not point to a folder. Exiting...")
        return False

    if not os.access(folder_path, os.R_OK):
        __LOGGER.error("Folder path is not readable. Exiting...")
        return False

    return True

def is_file_exist(file_path: str) -> bool:

    """
        Check if a file exists
        + file_path -> path to the file

        ⮕ Return True if the file exists, False otherwise
    """

    if not os.path.exists(file_path):
        __LOGGER.error("File path does not exist. Exiting...")
        return False

    if not os.path.isfile(file_path):
        __LOGGER.error("File path does not point to a file. Exiting...")
        return False

    if not os.access(file_path, os.R_OK):
        __LOGGER.error("File path is not readable. Exiting...")
        return False

    return True