import fitz # PyMuPDF
import pathlib
import sys

sys.path.append(str(pathlib.Path(__file__).parent.resolve()))

from Utile import keep_only_numbers, execute_command

class PdfAnalyseTools:

    """
        This class gathers tools methods to analyse a PDF
    """

    # Path to local folder
    __LOCAL_PATH = str(pathlib.Path(__file__).parent.resolve())

    # Path to the pdf file to analyse
    __file_path = ""

    # Constructor
    def __init__(self, file_path):
        self.__file_path = file_path
    
    def pdfid(self) -> dict:

        """
            This method wraps pdfid command

            ⮕ Return a dictionary with the result of the analysis
        """

        # Execute the pdfid command
        worked, lines = execute_command(['python3', self.__LOCAL_PATH + '/lib/pdfid.py', self.__file_path])

        if not worked:
            return None

        # If the file is not a PDF, return dictionary with isAValidPDF = False
        if "Not a PDF document" in lines[1]:
            return { "isAValidPDF": False }

        # Strip all the lines
        for i in range(len(lines)):
            lines[i] = lines[i].strip()

        # Return the dictionary with the result of the analysis
        return {
            "isAValidPDF": True,
            "header": lines[1].strip(),
            "obj": int(keep_only_numbers(lines[2])),
            "endobj": int(keep_only_numbers(lines[3])),
            "stream": int(keep_only_numbers(lines[4])),
            "endstream": int(keep_only_numbers(lines[5])),
            "xref": int(keep_only_numbers(lines[6])),
            "trailer": int(keep_only_numbers(lines[7])),
            "startxref": int(keep_only_numbers(lines[8])),
            "Page": int(keep_only_numbers(lines[9])),
            "Encrypt": int(keep_only_numbers(lines[10])),
            "ObjStm": int(keep_only_numbers(lines[11])),
            "JS": int(keep_only_numbers(lines[12])),
            "JavaScript": int(keep_only_numbers(lines[13])),
            "AA": int(keep_only_numbers(lines[14])),
            "OpenAction": int(keep_only_numbers(lines[15])),
            "AcroForm": int(keep_only_numbers(lines[16])),
            "JBIG2Decode": int(keep_only_numbers(lines[17])[1:]),
            "RichMedia": int(keep_only_numbers(lines[18])),
            "Launch": int(keep_only_numbers(lines[19])),
            "EmbeddedFile": int(keep_only_numbers(lines[20])),
            "XFA": int(keep_only_numbers(lines[21])),
            "Colors": int(keep_only_numbers(lines[22])[3:])
        }
    
    def get_search_keywords(self) -> dict:

        """
            This method use pdf-parser command to search for keywords and the number of objects associated in the PDF

            ⮕ Return a dictionary with the result of the analysis
        """

        __KEYWORDS = ["URI", "JS", "JavaScript", "AA", "OpenAction", "Launch", "AcroForm"]

        # -a: display stats
        # -O: parse stream of /ObjStm objects
        worked, lines = execute_command(['python3', self.__LOCAL_PATH + '/lib/pdf-parser.py', '-a', '-O', self.__file_path])

        # If not worked, try without -O
        if not worked:
            worked, lines = execute_command(['pdf-parser', '-a', self.__file_path])
            if not worked:
                return None

        # Construct the dictionary result with the keywords
        res = {}
        for keyword in __KEYWORDS:
            res[keyword] = []

        # Parse lines until find "Search keywords"
        keywords_present = False
        for line in lines:

            if line == "":
                continue

            if not keywords_present and "Search keywords" in line:
                keywords_present = True
                continue
            
            # If keywords are present, parse the lines
            if keywords_present:

                # Search keyword in line among the list of keywords
                keyword = ""
                for keyword in __KEYWORDS:
                    if keyword in line:
                        keyword = keyword
                        break
                # If keyword not found, continue to the next line
                if keyword == "":
                    continue
                
                res_list = []

                # Get the number of objects in cpt variable, and the list of number objects in list_of_values
                tmp = line.split(":")
                cpt = int(keep_only_numbers(tmp[0]))
                list_of_values = tmp[1].strip().replace(" ", "")
                
                # If only one object, add it to the list
                if cpt == 1:
                    res_list.append(int(keep_only_numbers(list_of_values)))
                # If more than one object, split the list of values and add them to the list
                else:
                    list_of_values = list_of_values.split(",")
                    list_of_values = [int(element) for element in list_of_values]
                    res_list = list_of_values

                # Add the list of objects to the dictionary
                res[keyword] = res_list

        return res
    
    def get_object(self, object_number: int) -> str:

        """
            This method use PyMuPDF to get the object at the given object number
            + object_number -> the object number

            ⮕ Return the object
        """

        doc = fitz.open(self.__file_path)
        return doc.xref_object(object_number, compressed=False)
    
    def get_metadata(self) -> dict:

        """
            This method use PyMuPDF to get the metadata of the PDF
            
            ⮕ Return the metadata
        """

        doc = fitz.open(self.__file_path)
        return doc.metadata
    
    def set_file_path(self, file_path: str):

        """
            This method set the file path
            + file_path -> the path to the PDF file
        """

        self.__file_path = file_path
    