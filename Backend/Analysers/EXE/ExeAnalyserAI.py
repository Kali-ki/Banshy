import os
import re
import pefile
import tensorflow as tf


def load_ai_model(model_path):
    """
    Chargement du modèle d'intelligence artificielle pré-entraîné pour la détection de fichiers malveillants.
    """
    model = tf.saved_model.load(model_path)
    return model

def analyze_pe_with_ai(pe_path, ai_model):
    """
    Analyse le fichier PE (Portable Executable) en utilisant un modèle d'intelligence artificielle pour détecter les fichiers malveillants.
    """
    pe = pefile.PE(pe_path)

    # Extraction des imports
    imports = []
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode().lower()
        for imp in entry.imports:
            func_name = imp.name.decode().lower()
            imports.append(f"{dll_name}: {func_name}")

    # Prétraitement des données pour l'IA
    data = " ".join(imports)

    # Utilisation du modèle d'IA pour prédire la malveillance
    prediction = ai_model.predict([data])
    malicious = prediction > 0.5

    return bool(malicious)

def main():
    pe_path = input("Entrez le chemin du fichier PE à analyser : ")
    ai_model_path = "path/to/your/ai/model"  # Chemin vers le modèle d'IA pré-entraîné
    if os.path.isfile(pe_path) and pe_path.lower().endswith(".exe"):
        # Chargement du modèle d'intelligence artificielle
        ai_model = load_ai_model(ai_model_path)
        
        # Analyse du fichier PE avec l'IA
        is_malicious = analyze_pe_with_ai(pe_path, ai_model)
        
        if is_malicious:
            print("Le fichier est probablement malveillant.")
        else:
            print("Le fichier semble sûr.")
    else:
        print("Le chemin spécifié n'est pas valide ou ne pointe pas vers un fichier PE.")

if __name__ == "__main__":
    main()
