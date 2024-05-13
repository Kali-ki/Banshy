import os
import sys
import time
import joblib
import typing
import pathlib
import logging

sys.path.append(str(pathlib.Path(__file__).parent.resolve()))

from PdfAnalyseTools import PdfAnalyseTools
from Utile import is_folder_exist, is_file_exist, shapped_dict

# Logger
__LOGGER = logging.getLogger(__name__)

# This file gathers methods to analyse pdf files and folders containing PDFs

# Default verbose state
__VERBOSE = False

# Probability threshold
__THRESHOLD_SAFE = 0.70

def analyse_folder(folder_path: str, verbose: bool = __VERBOSE) -> None:

    """
        Analyse a folder containing PDFs
        Display the number of malicious and safe PDFs
        + folder_path -> path to the folder containing the PDFs
        + verbose -> display the progress of the analysis
    """

    if is_folder_exist(folder_path):

        start = time.time()

        print("Starting analysis of PDFs in folder: ", folder_path, "\n")

        nmb_malicious = 0
        nmb_safe = 0

        for root, dirs, files in os.walk(folder_path):
            for file in files:

                if verbose:
                    print("\nAnalysing ", file, " ...")

                file_path = os.path.join(root, file)

                if analyse_file(file_path)[0]:
                    nmb_safe += 1
                else:
                    nmb_malicious += 1

                # Display completion and time
                progress = round((nmb_malicious + nmb_safe) / len(files) * 100)
                if not verbose:
                    sys.stdout.write('\r')
                    sys.stdout.write("%d seconds " % (time.time() - start))
                    sys.stdout.write("[%-20s] %d%%" % ('=' * (progress // 5), progress))
                    sys.stdout.flush()
                else:
                    # Display percentage of completion
                    print("Progress: ", progress, "%")
                    

        end = time.time()
        print("\n\nAnalysis completed in ", round(end - start, 2), " seconds")
        print("Number of malicious PDFs : ", nmb_malicious)
        print("Number of safe PDFs : ", nmb_safe)
        print("Total number of PDFs : ", nmb_malicious + nmb_safe)

def analyse_file(file_path: str, thresold : int = __THRESHOLD_SAFE, verbose: bool = __VERBOSE) -> typing.Tuple[bool, float]:

    """
        Check if a PDF is safe, with a random forest model
        + file_path -> path to the PDF
        
        ⮕ Return True if the PDF is safe, False otherwise, and the probability of being safe. 
        If an error occurs, return False and -1.0.
    """

    # Check if the file exists, if not return False
    if not is_file_exist(file_path):
        return False, -1.0

    # Analyse the PDF with the PdfAnalyseTools class
    tools = PdfAnalyseTools(file_path)

    # Use pdfid, if res_pdfid is None, return False
    res_pdfid = tools.pdfid()
    if res_pdfid is None:
        return False, -1.0

    # Use pdf_parser, if res_pdf_parser is None, return False
    res_pdf_parser = tools.get_search_keywords()
    if res_pdf_parser is None:
        return False, -1.0

    # Create a dataframe from the dictionaries
    df = shapped_dict(res_pdfid, res_pdf_parser)
    # Load the random forest model
    rf = joblib.load(os.path.dirname(os.path.realpath(__file__)) + "/random_forest_weight_v2.joblib")
    
    # Make a prediction
    probability_safe = rf.predict_proba(df)[0][1]

    __LOGGER.info("Probability of being safe: " + str(probability_safe))

    if probability_safe < __THRESHOLD_SAFE:
        return False, probability_safe
    
    return True, probability_safe
