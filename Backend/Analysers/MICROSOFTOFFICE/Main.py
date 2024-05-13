import logging
import os
import pathlib
import sys
import time
import shutil

sys.path.append(str(pathlib.Path(__file__).parent.resolve()))

#from PdfAnalyser import analyse_folder
from MicrosoftOfficeAnalyser import analyse_microsoft_office_file
from Utile import is_folder_exist
from zipfile import ZipFile

__LOGGER = logging.getLogger(__name__)

__LOCAL_PATH = str(pathlib.Path(__file__).parent.resolve())

# Default verbose state
__VERBOSE = False


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

def analyse_folder(folder_path: str, verbose: bool = __VERBOSE) -> None:

    """
        Analyse a folder containing files
        Display the number of malicious and safe files
        + folder_path -> path to the folder containing the files
        + verbose -> display the progress of the analysis
    """

    if is_folder_exist(folder_path):

        start = time.time()

        print("Starting analysis of files in folder: ", folder_path, "\n")

        nmb_malicious = 0
        nmb_safe = 0

        for root, dirs, files in os.walk(folder_path):
            for file in files:

                if verbose:
                    print("\nAnalysing ", file, " ...")

                file_path = os.path.join(root, file)

                if analyse_microsoft_office_file(file_path):
                    nmb_malicious += 1
                else:
                    nmb_safe += 1

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
        print("Number of malicious files : ", nmb_malicious)
        print("Number of safe files : ", nmb_safe)
        print("Total number of files : ", nmb_malicious + nmb_safe)
        percentage_detected_infected = (nmb_malicious / (nmb_malicious + nmb_safe)) * 100
        percentage_detected_safe = (nmb_safe / (nmb_malicious + nmb_safe)) * 100
        print("Pourcentage de fichiers malveillants détectés : %.2f%%" % percentage_detected_infected)
        print("Pourcentage de fichiers sains détectés : %.2f%%" % percentage_detected_safe)

        shutil.rmtree(folder_path)


def unzip(filepath, outdir):
    import zipfile

    with zipfile.ZipFile(filepath, "r") as zip_ref:
        zip_ref.extractall(outdir)
    

if __name__ == "__main__":
    unzip(__LOCAL_PATH + "/../../DataSamples/MICROSOFTOFFICEs/Infected_microsoftoffice.zip","/home/morlot--pinta/Documents/Banshy/Backend/Analysers/MICROSOFTOFFICE/")
    unzip(__LOCAL_PATH + "/../../DataSamples/MICROSOFTOFFICEs/Safe_microsoftoffice.zip","/home/morlot--pinta/Documents/Banshy/Backend/Analysers/MICROSOFTOFFICE/")
    analyse_folder(__LOCAL_PATH + "/../../Analysers/MICROSOFTOFFICE/Infected_microsoftoffice/",False)
    analyse_folder(__LOCAL_PATH + "/../../Analysers/MICROSOFTOFFICE/Safe_microsoftoffice/",False)
    
