// popup.js
document.addEventListener('DOMContentLoaded', function () {
  //var toggleButton = document.getElementById('toggleButton');
  var recentDownloadsList = document.getElementById('recentDownloadsList');
  var downloadsHiddenList = document.getElementById('downloadsHiddenList');
  var switchElement = document.getElementById('switch');
  var flechesContainer = document.querySelector('.fleches-container');

  flechesContainer.addEventListener('click', function() {
    // Sélectionne tous les spans avec la classe "fleche" à l'intérieur de flechesContainer
    var fleches = flechesContainer.querySelectorAll('.fleche');

    if (downloadsHiddenList.style.display === 'none') {
        downloadsHiddenList.style.display = 'block'; // Affiche la liste complète
        //toggleButton.classList.toggle("active");
        //toggleButton.textContent = 'Cacher les téléchargements'; // Change le texte du bouton
    } else {
        downloadsHiddenList.style.display = 'none'; // Cache la liste complète
        //toggleButton.classList.toggle("active");
        //toggleButton.textContent = 'Afficher les téléchargements'; // Change le texte du bouton
    }
    
    // Parcourt chaque span et inverse sa classe
    fleches.forEach(span => {
      span.classList.toggle('inverse');
    });
  });


    chrome.storage.local.get('switchValue', function(data) {
        const switchValue = data.switchValue;

        const checkbox = switchElement.querySelector('input[type="checkbox"]');

        if (switchValue) {
            checkbox.checked = true;
            switchElement.classList.add('active');
            //console.log(switchElement.classList);
        } else { 
            checkbox.checked = false;
            switchElement.classList.remove('active');
            //console.log(switchElement.classList);
        }
    })

//   // Fonction pour mettre à jour le contenu de la liste de téléchargements
//   function updateDownloadsList(downloads) {
//       var ul = downloadsList.querySelector('ul');
//       ul.innerHTML = ''; // Vide le contenu précédent

//     downloads.forEach(function (download) {
//         var li = document.createElement('li');
//         // Crée un élément span à partir de la chaîne HTML
//         var span = document.createElement('span');
//         span.innerHTML = download.trim(); // Treat download as a string
    
//         // Ajoute l'élément span à l'élément li
//         li.appendChild(span.firstChild);
    
//         ul.appendChild(li);
//     });
//   }


function updateDownloadsList(downloads) {
    //console.log("J'y fut");
    var ul = recentDownloadsList.querySelector('ul');
    ul.innerHTML = ''; // Vide le contenu précédent

    // Crée une liste cachée pour les téléchargements restants
    var hiddenUl = downloadsHiddenList.querySelector('ul');
    ul.innerHTML = '';
    //hiddenUl.style.display = 'none'; // Cache la liste par défaut

    // Affiche seulement les 3 derniers téléchargements s'ils sont disponibles
    //var startIndex = Math.max(0, 3);
    //var recentDownloads = downloads.slice(startIndex);

    var recentDownloads = downloads.slice(0,3); // Récupère les 3 derniers éléments


    recentDownloads.forEach(function (download) {
        var li = document.createElement('li');
        var span = document.createElement('span');
        span.innerHTML = download.trim();
        li.appendChild(span);
        ul.appendChild(li);
    });

    // Ajoute les téléchargements restants à la liste cachée
    // downloads.slice(0, startIndex).forEach(function (download) {
        downloads.slice(3, 10).forEach(function (download) {

        var li = document.createElement('li');
        var span = document.createElement('span');
        span.innerHTML = download.trim();
        li.appendChild(span);
        hiddenUl.appendChild(li);
    });
}


//   // Fonction pour afficher ou masquer la liste de téléchargements lorsque le bouton est cliqué
//   toggleButton.addEventListener('click', function() {
//       if (downloadsList.style.display === 'none') {
//           downloadsList.style.display = 'block';
//       } else {
//           downloadsList.style.display = 'none';
//       }
//   });

//   toggleButton.addEventListener('click', function() {
    
//     if (downloadsHiddenList.style.display === 'none') {
//         downloadsHiddenList.style.display = 'block'; // Affiche la liste complète
//         toggleButton.classList.toggle("active");
//         //toggleButton.textContent = 'Cacher les téléchargements'; // Change le texte du bouton
//     } else {
//         downloadsHiddenList.style.display = 'none'; // Cache la liste complète
//         toggleButton.classList.toggle("active");
//         //toggleButton.textContent = 'Afficher les téléchargements'; // Change le texte du bouton
//     }
// });

  switchElement.addEventListener('click', function() {
        // Récupérer la valeur actuelle du switch
        chrome.storage.local.get('switchValue', function(data) {
            const currentSwitchValue = data.switchValue;
  
            // Inverser la valeur du switch
            const newSwitchValue = !currentSwitchValue;
            const checkbox = switchElement.querySelector('input[type="checkbox"]');

            // Stocker la nouvelle valeur dans chrome.storage.local
            chrome.storage.local.set({ switchValue: newSwitchValue });
            //console.log(switchElement.classList.toString)

            if (newSwitchValue) {
                checkbox.checked = true;
                switchElement.classList.add('active');
                //console.log(switchElement.classList);
            } else { 
                checkbox.checked = false;
                switchElement.classList.remove('active');
                //console.log(switchElement.classList);
    
            }
        });
    });

  // Écoute les messages provenant du fond (background.js)
  chrome.runtime.onMessage.addListener(function (message) {
      if (message.downloads) {
          // Met à jour le contenu de la liste de téléchargements
          updateDownloadsList(message.downloads);
      } else if (message.action === 'updatePopup') {
          // Si un message d'actualisation est reçu, récupère le nom du fichier depuis chrome.storage
          chrome.storage.local.get('filename', function (data) {
              updateDownloadsList(data.filename);
          });
      }
  });

//   // Récupère la liste des téléchargements depuis chrome.storage lors de l'ouverture du popup
//   chrome.storage.local.get({downloads: []}, function (data) {
//       updateDownloadsList(data.downloads);
//   });

chrome.storage.local.get({downloads: []}, function (data) {
    //updateDownloadsList(data.downloads, document.getElementById('recentDownloadsList'));
    updateDownloadsList(data.downloads);
});

});