# Banshy

Banshy is a web extension that downloads and analyzes files in cloud, before downloading them to your computer.

![image](./Project%20Management/Weekly%20Reports/images/banshy_extension.gif)

When you click on a download, the extension blocks the download,then the backend downloads and analyzes the file, and returns the result to the front to releases the download or not.

⚠️ **This project is still in development. Some updates should come in the futur.**
**See last section of this page.**

# 🚀 Performances

Banshy does not yet analyze all type of files. Let's see the performances of each type of files :

| Type File | Well predicted    | Analyze type          |
| :-------- | :---------------: | :--------------------:|
| PDF       |   97%             | AI (random forests)   |
| EXE       |   49%             | Static analyzed       |
| MIC       |   43%             | Static analyzed       |

# 💻 Install Banshy

## 🔌 Install extension

For now, the extension is only available for chromium browser (like chrome, Opera, Brave, ...).

- 1 - Go to extension paramaters on your chromium browser.

- 2 - Select "Load unpacker".

- 3 - Choose folder `Frontend` of the Banshy project.

## 🐋 Launch backend with Docker

To start the backend, you need Docker and Docker Compose.

- 1 - Go on `Backend` folder

- 2 - Use command : `docker compose up -d`

- 3 - To stop it : `docker compose down`

## ⚓ Launch backend with Kubernetes

The backend can also be launched with Kubernetes.

- 1 - Go on `Kubernetes_Backend` folder
- 2 - Read `README.md`

# 🚧 Improvements

**This is an open source project, feel free to contribute or suggest any ideas.**

Here is the list of all improvements that are planed :

- Create analyzers for : 

    - 1 - Office documents (.docx, .xlsx, .pptx, ...)
    - 2 - Compresed files (.zip, .rar, .7z)
    - 3 - HTML and JS (.html, .js)
    - 4 - DLL (.dll)
    - 5 - Installation files (.msi, .msix, ...)
    - 6 - Image files (.img, .iso)

- Find more PDF files. The current model for PDF prediction has been trained on a dataset of 800 PDFs.
But, it is too limited to say that the model can be applied to any PDF.

- Add Banshy extension to web store

- Host backend in a server
