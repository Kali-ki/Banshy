import pathlib
import sys

sys.path.append(str(pathlib.Path(__file__).parent.resolve()))

from PdfAnalyser import analyse_folder, analyse_file
from CreateDataSet import create_dataset

__LOCAL_PATH = str(pathlib.Path(__file__).parent.resolve())

def main():

    """
        This main method is used to test the pdf analyser
    """

    file_path = __LOCAL_PATH + "/../../DataSamples/PDFs/Infected/Short/1.pdf"
    folder_path_infected = __LOCAL_PATH + "/../../DataSamples/PDFs/Infected/Short/"
    folder_path_safe = __LOCAL_PATH + "/../../DataSamples/PDFs/Safe/Short/"

    # Analyses
    # analyse_file(file_path)
    # analyse_folder(folder_path_safe)

    # Create datasets
    # print("\n\nCreating dataset infected ... \n")
    # create_dataset(folder_path_infected, "infected_pdf_dataset_short")
    # print("\n\nCreating dataset Safe ... \n")
    # create_dataset(folder_path_safe, "safe_pdf_dataset_short")

if __name__ == '__main__':
    main()