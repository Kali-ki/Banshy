chrome.runtime.sendMessage({ contentScriptLoaded: true });

chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
    if (message.action === 'showAlert') {
      alert(`Le fichier ${message.fileName} n'est pas sécurisé`);
    }
  });