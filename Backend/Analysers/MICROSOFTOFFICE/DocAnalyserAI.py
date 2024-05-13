import os
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics import accuracy_score

# Chargement des données simulées (exemple)
def load_data():
    # Chemin vers le dossier contenant les fichiers
    data_dir = "C:\\Users\\utilisateur\\Documents\\UQAC\\Hiver\\Atelier pratique cybersécurité II\\Banshy\\Backend\\DataSamples\\Docxs"
    documents = []
    labels = []

    # Parcours de chaque fichier dans le dossier
    for filename in os.listdir(data_dir):
        with open(os.path.join(data_dir, filename), 'r', encoding='utf-8') as file:
            content = file.read()
            documents.append(content)
            # Exemple : si le nom du fichier commence par "malware_", le label est 1 (malveillant), sinon 0 (non malveillant)
            labels.append(1 if filename.startswith("malware_") else 0)

    return documents, labels

# Chargement des données
documents, labels = load_data()

# Vectorisation des documents
vectorizer = CountVectorizer()
X = vectorizer.fit_transform(documents)
y = np.array(labels)

# Division des données en ensembles d'entraînement et de test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Entraînement du modèle de classification par forêt aléatoire
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Prédiction sur l'ensemble de test
y_pred = clf.predict(X_test)

# Évaluation de la performance du modèle
accuracy = accuracy_score(y_test, y_pred)
print("Accuracy:", accuracy)
