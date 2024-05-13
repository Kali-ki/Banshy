// chrome.runtime.onInstalled.addListener(function() {
//   chrome.storage.local.set({ switchValue: true});
// })

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({ switchValue: true});

  // chrome.declarativeNetRequest.getEnabledRulesets((rulesets) => {
  //   if (chrome.runtime.lastError) {
  //     console.error("Erreur lors de la récupération des ensembles de règles :", chrome.runtime.lastError.message);
  //     return;
  //   }
  
  //   console.log("Ensembles de règles activés :", rulesets);
  });  


chrome.downloads.onCreated.addListener((downloadItem) => {
  if(downloadItem.state != "complete" && downloadItem.state != "interrupted"){
  // Récupérer la valeur actuelle du switch
  chrome.storage.local.get('switchValue', function(data) {
  const switchValue = data.switchValue;
  //console.log("Valeur du switch :", switchValue);
  console.log(downloadItem);
  const downloadId = downloadItem.id;
  let downloadUrl = downloadItem.finalUrl.replace(/"/g, "'");
  let status = 'none' 
  let validType = true;
  if(switchValue){
    //console.log("download")
    //console.log(downloadItem.finalUrl)
    chrome.downloads.pause(
      downloadId, ()=> {
        downloadItem.paused = true;
        const url = 'http://127.0.0.1:5000/isSafe';
        const data = {
          url: downloadUrl
        };

        const requestOptions = {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(data)
        };
        //console.log('Request URL:', url);
        //console.log('Request Options:', requestOptions);
        fetch(url, requestOptions)
          .then(response => {
            //console.log('Response Status:', response.status);
            return response.text(); // Traitement en tant que texte
          })
          .then(result => {
            //console.log('Response Body:', result);

            //Fichier safe
            if (result.includes('is safe')) {
              //if(false){
              //if(true){
              status = 'safe';
              handleDownload(downloadId,status)
              chrome.downloads.resume(downloadId, function() {
                if (chrome.runtime.lastError) {
                  console.error(chrome.runtime.lastError.message);
                } else {
                  //console.log(`Download ${downloadId} resumed.`);
                }
              });
              //Fichier non safe
            } else if (result.includes('is not safe')) {
            //}else if(true) {
              status = 'unsafe';
              let name = getFileNameFromUrl(downloadItem.url)
              showNotification(name)
              handleDownload(downloadId,status)
              chrome.downloads.cancel(downloadId, function() {
                if (chrome.runtime.lastError) {
                  console.error(chrome.runtime.lastError.message);
                } else {
                  //console.log(`Download ${downloadId} cancelled.`);
                }
              });
            } else {
              status = 'none';
            }
          })
          .catch(error => {
            console.error('Error:', error);
          });
      }
    )
  }else {
    handleDownload(downloadId,status)
  }
  //console.log(downloadItem);
  });}
});

function handleDownload(downloadId, status) {
  chrome.downloads.search({id:downloadId}, (downloadItems)=> {
    if (downloadItems && downloadItems.length > 0) {
      const downloadedUrl = downloadItems[0].finalUrl;
      const downloadName = getFileNameFromUrl(downloadedUrl)
      chrome.storage.local.get({ downloads: [] }, function (data) {
        const downloadsList = data.downloads;
        //downloadsList.unshift(`<span class="${status}">${downloadName}</span>`); // Ajoute le nouvel URL au début de la liste
        downloadsList.unshift(`<span class="file-status ${status}">${downloadName}</span>`); // Ajoute le nouvel URL au début de la liste

        chrome.storage.local.set({ downloads: downloadsList });
        // Mets à jour l'icône de l'extension avec le nombre de téléchargements
        chrome.action.setBadgeText({ text: downloadsList.length.toString() });
      });
    }
  });
}



function getFileNameFromUrl(url) {
  const urlParts = url.split('/');
  const lastPart = urlParts[urlParts.length - 1];
  const fileName = decodeURIComponent(lastPart);
  return fileName;
}

function showNotification(name) {
  chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
    chrome.tabs.sendMessage(tabs[0].id, { action: 'showAlert', fileName: name });
  });
}