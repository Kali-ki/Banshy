import docx
import re

# Fonction pour extraire le texte d'un document DOCX
def extract_text_from_docx(docx_file):
    doc = docx.Document(docx_file)
    text = ""
    for paragraph in doc.paragraphs:
        text += paragraph.text + "\n"
    return text

# Fonction pour analyser le contenu extrait et déterminer s'il est malveillant
def analyze_docx_content(text):
    # Exemple d'analyse : recherche de la présence de certains mots-clés malveillants
    malicious_keywords = ["malware", "virus", "phishing", "exploit"]
    for keyword in malicious_keywords:
        if re.search(r'\b' + re.escape(keyword) + r'\b', text, re.IGNORECASE):
            return True
    return False

# Fonction principale pour analyser un document DOCX
def analyze_docx(docx_file):
    # Extraction du texte du document
    text = extract_text_from_docx(docx_file)
    # Analyse du contenu pour détecter la malveillance
    is_malicious = analyze_docx_content(text)
    return is_malicious

# Chemin vers le document DOCX à analyser
docx_file_path = "C:\\Users\\utilisateur\\Downloads\\Projet 2.1.docx"

# Analyse du document DOCX
if analyze_docx(docx_file_path):
    print("Le document est probablement malveillant.")
else:
    print("Le document semble sûr.")
