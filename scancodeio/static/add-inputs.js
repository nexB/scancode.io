// SPDX-License-Identifier: Apache-2.0
//
// http://nexb.com and https://github.com/nexB/scancode.io
// The ScanCode.io software is licensed under the Apache License version 2.0.
// Data generated with ScanCode.io is provided as-is without warranties.
// ScanCode is a trademark of nexB Inc.
//
// You may not use this software except in compliance with the License.
// You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// Data Generated with ScanCode.io is provided on an "AS IS" BASIS, WITHOUT WARRANTIES
// OR CONDITIONS OF ANY KIND, either express or implied. No content created from
// ScanCode.io should be considered or used as legal advice. Consult an Attorney
// for any legal advice.
//
// ScanCode.io is a free software code scanning tool from nexB Inc. and others.
// Visit https://github.com/nexB/scancode.io for support and download.

const fileInput = document.querySelector('#id_input_files');
let selectedFiles = []; // Store selected files

fileInput.onchange = updateFiles;

// Update the list of files to be uploaded in the UI
function updateFiles() {
  if (fileInput.files.length > 0) {
    const fileName = document.querySelector('#inputs_file_name');
    fileName.innerHTML = "";

    // Update the selectedFiles array
    const newFiles = Array.from(fileInput.files);
    // Create a Set to track unique file names
    const uniqueFileNames = new Set(selectedFiles.map(file => file.name));
    // Filter out files with the same name
    const filteredNewFiles = newFiles.filter(file => !uniqueFileNames.has(file.name));
    // Concatenate the unique files to the existing selectedFiles array
    selectedFiles = selectedFiles.concat(filteredNewFiles);

    for (let file of selectedFiles) {
      const fileNameWithoutSpaces = file.name.replace(/\s/g, '');
      fileName.innerHTML += `
      <span class="is-flex is-justify-content-space-between is-block" id="file-name-${fileNameWithoutSpaces}">
        <span class="is-block">${file.name}</span>
        <a href="#" onclick="removeFile('${fileNameWithoutSpaces}')" class="model-button" id="file-delete-btn-${fileNameWithoutSpaces}">
          <i class="fa-solid fa-trash-can mr-2"></i>
        </a>
      </span>
      `;
      document.getElementById("file-delete-btn-"+ fileNameWithoutSpaces).addEventListener("click", function(event){
        disableEvent(event);
        removeFile(fileNameWithoutSpaces);
        if(selectedFiles.length == 0){
          fileName.innerHTML ="<i>No files selected</i>"
        }
      });
    }
  }
}

// Prevent default behavior (prevent file from being opened)
function disableEvent(event) {
  event.stopPropagation();
  event.preventDefault();
}

function removeFile(fileName) {
  selectedFiles = selectedFiles.filter(file => {
    const fileNameWithoutSpaces = file.name.replace(/\s/g, '');
    return fileNameWithoutSpaces !== fileName;
  });

  const fileNameElement = document.getElementById(`file-name-${fileName}`);
  if (fileNameElement) {
    fileNameElement.remove();
  }

  const dataTransfer = new DataTransfer();
  for (let file of selectedFiles) {
    dataTransfer.items.add(file);
  }

  fileInput.files = dataTransfer.files;
}

function dropHandler(event) {
  disableEvent(event);
  const droppedFiles = event.dataTransfer.files;
  const updatedFilesSet = new Set(Array.from(fileInput.files));
  
  for (let file of droppedFiles) {
    updatedFilesSet.add(file);
  }
  
  // Convert the Set back to an array if needed
  const updatedFiles = Array.from(updatedFilesSet);
  const dataTransfer = new DataTransfer();
  for (let file of updatedFiles) {
    dataTransfer.items.add(file);
  }
  
  fileInput.files = dataTransfer.files;
  updateFiles();
}

// Handle drag and drop events
const inputFilesBox = document.querySelector('#input_files_box');
inputFilesBox.addEventListener("dragenter", disableEvent);
inputFilesBox.addEventListener("dragover", disableEvent);
inputFilesBox.addEventListener("drop", dropHandler);
