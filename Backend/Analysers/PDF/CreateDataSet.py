import pandas as pd
import os
import sys
import time
import pathlib

sys.path.append(str(pathlib.Path(__file__).parent.resolve()))

from PdfAnalyseTools import PdfAnalyseTools
from Utile import shapped_dict    

def create_dataset(folder_path: str, name_of_dataset: str) -> None:

    """
        This function creates a dataset from a folder containing PDF files.
        The dataset is saved as an excel file.
        + folder_path -> The path to the folder containing the PDF files.
        + name_of_dataset -> The name of the dataset to be created.
    """

    file_name = name_of_dataset+".xlsx"
    res = [] # This array will contain the dataframes

    start = time.time()

    for root, _, files in os.walk(folder_path):
                
                # Count the number of files added
                cpt_files_added = 0
                
                tool = PdfAnalyseTools("")

                for file_ in files:
                    file = os.path.join(root, file_) # Get the file path

                    # Set the file path in the PdfAnalyseTools object
                    tool.set_file_path(file)
                    # Analyse the file
                    pdfid_dict = tool.pdfid()
                    pdf_parser_dict = tool.get_search_keywords()

                    if pdfid_dict is None or pdf_parser_dict is None:
                        continue

                    # Create a dataframe from the dictionaries
                    df = shapped_dict(pdfid_dict, pdf_parser_dict)

                    # Add the file_ name to the dataframe
                    df['file_name'] = file_
                    # Move column file_name to the first position
                    cols = list(df.columns)
                    cols = [cols[-1]] + cols[:-1]
                    df = df[cols]

                    # Add the dictionary to the array
                    res.append(df)

                    # Display completion and time
                    cpt_files_added += 1
                    progress = round(cpt_files_added / len(files) * 100)
                    sys.stdout.write('\r')
                    sys.stdout.write(file_)
                    sys.stdout.write(" %d seconds " % (time.time() - start))
                    sys.stdout.write("[%-20s] %d%%" % ('=' * (progress // 5), progress))
                    sys.stdout.flush()
                    

    # Merge all dataframes of res into one dataframe
    df = pd.concat(res, ignore_index=True)

    # Save the dataset as an excel file
    df.to_excel(file_name)

    # Display the time taken to create the dataset
    end = time.time()
    print("\n\nDataset "+file_name+" created in", round(end - start, 2), "seconds")
    