//
// Selected parts from https://bulma.io/lib/main.js?v=202104191409
//

'use strict';

let rootEl = document.documentElement;

// Modals

// Opens that `target` modal
function openModal(target) {
  var $target = document.getElementById(target);
  rootEl.classList.add('is-clipped');
  $target.classList.add('is-active');
}

// Close all modals
function closeModals() {
  var $modals = getAll('.modal');

  rootEl.classList.remove('is-clipped');
  $modals.forEach(function ($el) {
    $el.classList.remove('is-active');
  });
}

// Setup modal buttons to open the related modal on click
function setupOpenModalButtons() {
  var $modalButtons = getAll('.modal-button');

  if ($modalButtons.length > 0) {
    $modalButtons.forEach(function ($el) {
      $el.addEventListener('click', function () {
        var target = $el.dataset.target;
        // Fire a custom event on opening a Modal
        document.dispatchEvent(new CustomEvent("openModal", {
          detail: {modal: target, $button: $el}
        }));
        openModal(target);
      });
    });
  }
}

// Setup modal close buttons to close modals on click
// The "is-no-close" class can be used to bypass the close behavior
function setupCloseModalButtons() {
  var $modalCloses = getAll('.modal-background, .modal-close, .modal-card-head .delete, .modal-card-foot .button');

  if ($modalCloses.length > 0) {
    $modalCloses.forEach(function ($el) {
      if ($el.classList.contains('is-no-close')) return;
      $el.addEventListener('click', function () {
        closeModals();
      });
    });
  }
}

// Tabs

function activateTab(tabLink) {
  const tabsContainer = tabLink.closest('.tabs');
  if (!tabsContainer) return; // Safety check

  const tabs = tabsContainer.querySelectorAll('li');
  const tabContents = tabsContainer.parentNode.querySelectorAll('.tab-content');

  // Deactivate all tabs
  tabs.forEach(item => item.classList.remove('is-active'));
  // Deactivate all tab contents
  tabContents.forEach(content => content.classList.remove('is-active'));

  tabLink.parentNode.classList.add('is-active');
  const targetId = tabLink.getAttribute('data-target');
  const targetContent = tabsContainer.parentNode.querySelector(`#${targetId}`);
  if (targetContent) {
    targetContent.classList.add('is-active');
  }

  // Conditionally update the URL hash
  const storeInHash = !tabsContainer.classList.contains('disable-hash-storage');
  if (storeInHash) {
    document.location.hash = targetId.replace('tab-', '');
  }
}

function activateTabFromHash() {
  const hashValue = document.location.hash.slice(1); // Remove the '#' from the hash
  if (!hashValue) return;

  const tabLink = document.querySelector(`a[data-target="tab-${hashValue}"]`);
  if (tabLink) {
    activateTab(tabLink);
  }
}

function setupTabs() {
  const tabsContainers = document.querySelectorAll('.tabs');

  tabsContainers.forEach(tabsContainer => {
    const tabLinks = tabsContainer.querySelectorAll('a[data-target]');

    tabLinks.forEach(tabLink => {
      tabLink.addEventListener('click', (event) => {
        event.preventDefault(); // Prevent the default behavior of the anchor tag
        activateTab(tabLink);
      });
    });
  });

  // Activate the related tab if hash is present in the URL on page loading
   activateTabFromHash();
  // Enable tab history navigation (using previous/next browser button for example)
  // by detecting URL hash changes.
   window.addEventListener("hashchange", activateTabFromHash);
}

// Menu

function setupMenu() {
  const $menuLinks = getAll('.menu a:not(.is-stateless)');

  function activateMenuItem($menuItem) {
    const activeLink = document.querySelector('.menu .is-active');
    activeLink.classList.remove('is-active');
    $menuItem.classList.add('is-active');
  }

  $menuLinks.forEach(function ($el) {
    $el.addEventListener('click', function () {
      activateMenuItem($el)
    });
  });
}

// Form

// Dynamic size for the textarea
function setupTextarea() {
  const $dynamicTextareas = getAll('textarea.is-dynamic');

  function setHeight($el) {
    $el.style.height = "";
    $el.style.height = $el.scrollHeight + 3 + "px";
  }

  $dynamicTextareas.forEach(function ($el) {
    $el.oninput = () => { setHeight($el); }
    $el.onfocus = () => { setHeight($el); }
  });
}

// Highlights

function setupHighlightControls() {
  const $highlightShows = getAll(".is-more-show");

  $highlightShows.forEach(function ($el) {
    const parentDiv = $el.parentNode;

    if (parentDiv.scrollHeight <= 250) {
      $el.style.display = "none";
    } else {
      $el.addEventListener("click", function () {
        let text = $el.querySelector("strong").textContent;
        let newText = text === "Show all" ? "Hide" : "Show all";
        $el.querySelector("strong").textContent = newText;
        $el.parentNode.classList.toggle("is-more-clipped");
      });
    }
  });
}

function setupSelectCheckbox() {
  // Get references to the header checkbox and all row checkboxes
  const selectAllCheckbox = document.getElementById("select-all");
  const rowCheckboxes = document.querySelectorAll(".select-row");
  let lastChecked; // Variable to store the last checked checkbox
  const actionDropdown = document.getElementById("list-actions-dropdown");
  const dropdownButton = document.querySelector("#list-actions-dropdown button");

  // Check if selectAllCheckbox or actionDropdown does not exist before proceeding
  if (!selectAllCheckbox || !actionDropdown) return;

  // Check if at least one row is checked and update the elements state accordingly
  function updateButtonAndDropdownState() {
    const atLeastOneChecked = Array.from(rowCheckboxes).some((cb) => cb.checked);

    // Toggle the 'is-disabled' class and 'disabled' attribute of the button
    if (atLeastOneChecked) {
      actionDropdown.classList.remove("is-disabled");
      dropdownButton.removeAttribute("disabled");
    } else {
      actionDropdown.classList.add("is-disabled");
      dropdownButton.setAttribute("disabled", "disabled");
    }
  }

  // Add a click event listener to the "Select All" checkbox
  selectAllCheckbox.addEventListener("click", function () {
    // Toggle the selection of all row checkboxes
    rowCheckboxes.forEach((checkbox) => {
      checkbox.checked = selectAllCheckbox.checked;
    });

    updateButtonAndDropdownState();
  });

  // Add a click event listener to each row checkbox to handle individual selections
  rowCheckboxes.forEach((checkbox) => {
    checkbox.addEventListener("click", function (event) {
      if (event.shiftKey && lastChecked) {
        // Determine the index of the clicked checkbox
        const currentCheckboxIndex = Array.from(rowCheckboxes).indexOf(checkbox);
        const lastCheckedIndex = Array.from(rowCheckboxes).indexOf(lastChecked);

        // Determine the range of checkboxes to check/uncheck
        const startIndex = Math.min(currentCheckboxIndex, lastCheckedIndex);
        const endIndex = Math.max(currentCheckboxIndex, lastCheckedIndex);

        // Toggle the checkboxes within the range
        for (let i = startIndex; i <= endIndex; i++) {
          rowCheckboxes[i].checked = checkbox.checked;
        }
      }

      // Update the last checked checkbox
      lastChecked = checkbox;

      updateButtonAndDropdownState();

      // Check if all row checkboxes are checked and update the "Select All" checkbox accordingly
      selectAllCheckbox.checked = Array.from(rowCheckboxes).every((cb) => cb.checked);
    });
  });

}

// Function to return currently selected checkboxes
function getSelectedCheckboxes() {
  const rowCheckboxes = document.querySelectorAll(".select-row");
  const selectedCheckboxes = [];
  rowCheckboxes.forEach((checkbox) => {
    if (checkbox.checked) {
      selectedCheckboxes.push(checkbox);
    }
  });
  return selectedCheckboxes;
}

// Utils, available globally

function getAll(selector) {
  var parent = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : document;
  return Array.prototype.slice.call(parent.querySelectorAll(selector), 0);
}

function displayOverlay() {
  const background = document.createElement("div");
  background.setAttribute("id", "background-overlay");
  background.className = "modal-background";
  background.style.cssText = "z-index:100;color:white;text-align:center;padding-top:150px;position:fixed;";
  background.innerHTML = '<div class="fa-5x"><i class="fas fa-circle-notch fa-spin"></i></div>';
  document.body.appendChild(background);
  return background;
}

function removeOverlay() {
  const background = document.getElementById("background-overlay");
  if (background) background.remove();
}

// Display and update the `$progress` object on `$form` submitted using XHR
function displayFormUploadProgress($form, $progress, $form_errors, update_title=false) {

 // Prepare an AJAX request to submit the form and track the progress
  let xhr = new XMLHttpRequest();

  // Submit the form using initial form attributes
  xhr.open($form.getAttribute('method'), $form.getAttribute('action'), true);
  xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');

  xhr.upload.addEventListener('progress', function(event) {
    console.log("XHR progress event fired");
    // Compute the progress percentage and set the value on the `progress` element
    if (event.lengthComputable) {
      let percent = (event.loaded / event.total * 100).toFixed();
      $progress.setAttribute('value', percent);
      if (update_title) document.title = `Uploading: ${percent}% - ScanCode.io`;
    }
  }, false);

  xhr.addEventListener('readystatechange', function(event) {
    let target = event.target;
    console.log("XHR readystatechange event fired");

    if (target.readyState === XMLHttpRequest.DONE) {
      if (target.status === 201) {
        let response_json = JSON.parse(target.response);
        window.location.replace(response_json['redirect_url']);
      }
      else if (target.status === 400) {
        let response_json = JSON.parse(target.response);
        $form_errors.innerHTML = response_json['errors'];
        $form_errors.classList.remove("is-hidden");
        // Remove the background
        $progress.parentNode.parentNode.remove();
      }
      else {
        throw new Error('Error.');
      }
    }
  }, false);

  xhr.send(new FormData($form));
}

document.addEventListener('DOMContentLoaded', function () {

  setupOpenModalButtons();
  setupCloseModalButtons();
  setupTabs();
  setupMenu();
  setupTextarea();
  setupHighlightControls();
  setupSelectCheckbox();

  // Close modals and dropdowns on pressing "escape" key
  document.addEventListener('keydown', function (event) {
    var e = event || window.event;

    if (e.keyCode === 27) {
      closeModals();
      closeDropdowns();
    }
  });

  // Dropdowns

  var $dropdowns = getAll('.dropdown:not(.is-hoverable)');

  if ($dropdowns.length > 0) {
    $dropdowns.forEach(function ($el) {
      $el.addEventListener('click', function (event) {
        event.stopPropagation();
        $el.classList.toggle('is-active');
      });
    });

    document.addEventListener('click', function (event) {
      closeDropdowns();
    });
  }

  function closeDropdowns() {
    $dropdowns.forEach(function ($el) {
      $el.classList.remove('is-active');
    });
  }

});

// Toasts (requires bulma-toast.js)

function displayPipelineStatusToast(run_status, pipeline_name, project_url) {
    const default_options = {
      "position": "top-center",
      "dismissible": true,
      "closeOnClick": false,
      "pauseOnHover": true,
      "duration": 30000 // 30 secs
    }
    let custom_options;

    if (run_status === "running") {
      custom_options = {
        "message": `Pipeline ${pipeline_name} started.`,
        "type": "is-info",
        "duration": 3000 // 3 secs
      }
    }
    else if (run_status === "success") {
      custom_options = {
        "message": `Pipeline ${pipeline_name} completed successfully.\n` +
                   `<a href="${project_url}">Access or refresh the project page for results.</a>`,
        "type": "is-success is-inline-block",
      }
    }
    else {
      custom_options = {
        "message": `Pipeline ${pipeline_name} ${run_status}.`,
        "type": "is-danger",
      }
    }

    bulmaToast.toast({...default_options, ...custom_options});
}

// Themes

const STORAGE_KEY = "bulma-theme";
const SYSTEM_THEME = "system";
const DEFAULT_THEME = "light";

const state = {
  chosenTheme: SYSTEM_THEME, // light|dark|system
  appliedTheme: DEFAULT_THEME, // light|dark
  OSTheme: null, // light|dark|null
};

//const $themeCycle = document.getElementById("js-cycle");
const $themeSwitchers = document.querySelectorAll(".js-themes button");

const updateThemeUI = () => {
//  if (state.appliedTheme === "light") {
//    $themeCycle.className = "bd-cycle js-burger is-sun";
//  } else {
//    $themeCycle.className = "bd-cycle js-burger is-moon";
//  }

  $themeSwitchers.forEach((el) => {
    const swatchTheme = el.dataset.scheme;

    if (state.chosenTheme === swatchTheme) {
      el.classList.add("is-active");
    } else {
      el.classList.remove("is-active");
    }
  });
};

const setTheme = (theme, save = true) => {
  state.chosenTheme = theme;
  state.appliedTheme = theme;

  if (theme === SYSTEM_THEME) {
    state.appliedTheme = state.OSTheme;
    document.documentElement.removeAttribute("data-theme");
    window.localStorage.removeItem(STORAGE_KEY);
  } else {
    document.documentElement.setAttribute("data-theme", theme);

    if (save) {
      window.localStorage.setItem(STORAGE_KEY, theme);
    }
  }

  updateThemeUI();
};

const toggleTheme = () => {
  if (state.appliedTheme === "light") {
    setTheme("dark");
  } else {
    setTheme("light");
  }
};

const detectOSTheme = () => {
  if (!window.matchMedia) {
    // matchMedia method not supported
    return DEFAULT_THEME;
  }

  if (window.matchMedia("(prefers-color-scheme: dark)").matches) {
    // OS theme setting detected as dark
    return "dark";
  } else if (window.matchMedia("(prefers-color-scheme: light)").matches) {
    return "light";
  }

  return DEFAULT_THEME;
};

// On load, check if any preference was saved
const localTheme = window.localStorage.getItem(STORAGE_KEY);
state.OSTheme = detectOSTheme();

if (localTheme) {
  setTheme(localTheme, false);
} else {
  setTheme(SYSTEM_THEME);
}

// Event listeners
$themeSwitchers.forEach((el) => {
  el.addEventListener("click", () => {
    const theme = el.dataset.scheme;
    setTheme(theme);
  });
});

window
  .matchMedia("(prefers-color-scheme: dark)")
  .addEventListener("change", (event) => {
    const theme = event.matches ? "dark" : "light";
    state.OSTheme = theme;
    setTheme(theme);
  });
