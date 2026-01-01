document.addEventListener("DOMContentLoaded", function () {
  const detailsPane = document.getElementById("detailsPane");
  const entriesListContainer = document.querySelector(".entries-list");
  let currentActiveEntryItem = null;

  const sortOptionsContainer = document.querySelector(".sort-options");
  if (sortOptionsContainer) {
    const initialSortBy =
      sortOptionsContainer.dataset.initialSortBy || "date_added";
    const initialOrder = sortOptionsContainer.dataset.initialOrder || "desc";
    updateSortButtonsUI(initialSortBy, initialOrder);
  }

  if (detailsPane) {
    const isDetailsPaneEssentiallyEmpty = detailsPane.innerHTML.trim() === "";
    const isFormAlreadyPresent = detailsPane.querySelector(
      "form.entry-details-form"
    );

    if (!isFormAlreadyPresent && isDetailsPaneEssentiallyEmpty) {
      showSelectEntryMessage();
    } else if (isFormAlreadyPresent) {
      attachDetailPaneEventListeners(detailsPane);
      initializeTooltips(detailsPane);
    }
  }

  function showLoadingState(pane = detailsPane, isListContainer = false) {
    if (pane) {
      if (isListContainer) {
        pane.innerHTML = `<div class="d-flex justify-content-center align-items-center p-3"><div class="spinner-border text-light spinner-border-sm" role="status"><span class="visually-hidden">Завантаження...</span></div></div>`;
      } else {
        pane.innerHTML = `
                <div class="d-flex justify-content-center align-items-center" style="min-height: 300px;">
                    <div class="spinner-border text-light" role="status">
                        <span class="visually-hidden">Завантаження...</span>
                    </div>
                </div>`;
      }
    }
  }

  function showDetailsError(
    message = "Не вдалося завантажити дані.",
    pane = detailsPane
  ) {
    if (pane) {
      pane.innerHTML = `<div class="alert alert-danger-custom p-4 text-center">${message}</div>`;
    }
  }

  function showSelectEntryMessage() {
    if (detailsPane) {
      detailsPane.innerHTML = `
              <div class="no-entry-selected p-4 text-center">
                  <i class="bi bi-info-circle display-4 mb-3"></i>
                  <h4>Оберіть запис зі списку</h4>
                  <p class="mb-0">або натисніть "Додати +", щоб створити новий.</p>
              </div>`;
    }
  }

  function fetchAndLoadFormContent(
    url,
    targetPane = detailsPane,
    entryIdForCancel = null
  ) {
    showLoadingState(targetPane);
    fetch(url)
      .then((response) => {
        if (!response.ok) {
          return response.text().then((text) => {
            throw new Error(
              `HTTP помилка! Статус: ${response.status}, Відповідь: ${text}`
            );
          });
        }
        return response.json();
      })
      .then((data) => {
        if (data.success && data.html) {
          targetPane.innerHTML = data.html;
          initializeTooltips(targetPane);
          attachDetailPaneEventListeners(targetPane, entryIdForCancel);
        } else {
          showDetailsError(
            data.error || "Не вдалося завантажити форму.",
            targetPane
          );
        }
      })
      .catch((error) => {
        console.error("Помилка завантаження форми:", error);
        showDetailsError(`Помилка завантаження: ${error.message}`, targetPane);
      });
  }

  function initializeTooltips(container = document) {
    const tooltipTriggerList = [].slice.call(
      container.querySelectorAll('[data-bs-toggle="tooltip"]')
    );
    tooltipTriggerList.map(function (tooltipTriggerEl) {
      return new bootstrap.Tooltip(tooltipTriggerEl);
    });
  }

  if (entriesListContainer) {
    entriesListContainer.addEventListener("click", function (event) {
      let targetElement = event.target.closest(".entry-item");
      if (targetElement && targetElement.classList.contains("entry-item")) {
        event.preventDefault();
        const entryId = targetElement.dataset.entryId;
        const viewUrl = targetElement.dataset.viewUrl;

        if (currentActiveEntryItem) {
          currentActiveEntryItem.classList.remove("active-entry");
        }
        targetElement.classList.add("active-entry");
        currentActiveEntryItem = targetElement;

        if (viewUrl) {
          fetchAndLoadFormContent(viewUrl, detailsPane, entryId);
        }
      }
    });
  }

  document.body.addEventListener("click", function (event) {
    const loadFormButton = event.target.closest(".btn-load-form-ajax");
    if (loadFormButton) {
      event.preventDefault();
      const formUrl = loadFormButton.dataset.formUrl;
      const targetPaneId = loadFormButton.dataset.targetPane;
      const targetPaneElement = document.querySelector(targetPaneId);
      if (formUrl && targetPaneElement) {
        if (currentActiveEntryItem) {
          currentActiveEntryItem.classList.remove("active-entry");
          currentActiveEntryItem = null;
        }
        fetchAndLoadFormContent(formUrl, targetPaneElement);
      }
    }
  });

  function attachDetailPaneEventListeners(
    paneElement = detailsPane,
    currentEntryIdForCancel = null
  ) {
    const editButton = paneElement.querySelector(".btn-edit-action");
    if (editButton) {
      editButton.addEventListener("click", function (e) {
        e.preventDefault();
        const editUrl = this.dataset.editUrl;
        if (editUrl) {
          fetchAndLoadFormContent(editUrl, paneElement, this.dataset.entryId);
        }
      });
    }

    const cancelButton = paneElement.querySelector(".btn-cancel-edit-action");
    if (cancelButton) {
      cancelButton.addEventListener("click", function (e) {
        e.preventDefault();
        const entryId = this.dataset.entryId || currentEntryIdForCancel;
        const viewUrl = this.dataset.viewUrl;
        if (entryId && viewUrl) {
          fetchAndLoadFormContent(viewUrl, paneElement, entryId);
        } else {
          showSelectEntryMessage();
          if (
            entriesListContainer &&
            entriesListContainer.querySelectorAll(".entry-item").length === 0
          ) {
            renderEntriesList(
              [],
              document.getElementById("searchInputField")
                ? document.getElementById("searchInputField").value.trim()
                : ""
            );
          }
        }
      });
    }

    const generatePasswordButtonForm = paneElement.querySelector(
      ".generate-password-form-btn"
    );
    if (generatePasswordButtonForm) {
      generatePasswordButtonForm.addEventListener("click", function () {
        const targetInputId = this.dataset.targetInputId;
        const passwordFieldForGenerator =
          document.getElementById(targetInputId);
        if (!passwordFieldForGenerator) return;
        const params = new URLSearchParams({
          length: 16,
          type: "strong",
          uppercase: true,
          lowercase: true,
          digits: true,
          special: true,
        });
        const apiUrl =
          typeof dashboardUrls !== "undefined" && dashboardUrls.generatePassword
            ? dashboardUrls.generatePassword
            : "/entries/api/generate-password";
        fetch(`${apiUrl}?${params.toString()}`)
          .then((response) => response.json())
          .then((data) => {
            if (data.success && data.password) {
              passwordFieldForGenerator.value = data.password;
              const oldType = passwordFieldForGenerator.type;
              passwordFieldForGenerator.type = "text";
              setTimeout(() => {
                passwordFieldForGenerator.type = oldType;
              }, 2000);
            } else {
              displayFlashMessage(
                data.error || "Не вдалося згенерувати пароль.",
                "danger"
              );
            }
          })
          .catch((error) => {
            console.error("Error generating password:", error);
            displayFlashMessage("Помилка при генерації пароля.", "danger");
          });
      });
    }

    const entryForm = paneElement.querySelector("form.entry-details-form");
    if (entryForm) {
      entryForm.addEventListener("submit", function (e) {
        e.preventDefault();
        const formData = new FormData(entryForm);
        const actionUrl = entryForm.action;
        const method = entryForm.method;
        const submitButton = entryForm.querySelector('button[type="submit"]');
        const originalButtonText = submitButton ? submitButton.innerHTML : null;

        if (submitButton) {
          submitButton.disabled = true;
          submitButton.innerHTML =
            '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Збереження...';
        }

        fetch(actionUrl, {
          method: method,
          body: formData,
          headers: { "X-Requested-With": "XMLHttpRequest" },
        })
          .then((response) => response.json())
          .then((data) => {
            if (submitButton) {
              submitButton.disabled = false;
              submitButton.innerHTML = originalButtonText;
            }
            if (data.success) {
              displayFlashMessage(data.message, "success");
              if (data.entry && data.entry.entry_id) {
                let existingListItem = entriesListContainer.querySelector(
                  `.entry-item[data-entry-id="${data.entry.entry_id}"]`
                );
                const effectivelyNew = !existingListItem;

                updateEntriesList(data.entry, effectivelyNew);

                fetchAndLoadFormContent(
                  data.entry.view_url,
                  paneElement,
                  data.entry.entry_id
                );

                const newActiveItemInList = entriesListContainer.querySelector(
                  `.entry-item[data-entry-id="${data.entry.entry_id}"]`
                );
                if (newActiveItemInList) {
                  if (currentActiveEntryItem)
                    currentActiveEntryItem.classList.remove("active-entry");
                  newActiveItemInList.classList.add("active-entry");
                  currentActiveEntryItem = newActiveItemInList;
                }
              } else {
                showSelectEntryMessage();
                if (
                  entriesListContainer.querySelectorAll(".entry-item")
                    .length === 0
                ) {
                  renderEntriesList(
                    [],
                    document.getElementById("searchInputField")
                      ? document.getElementById("searchInputField").value.trim()
                      : ""
                  );
                }
              }
            } else {
              displayFlashMessage(data.error || "Сталася помилка.", "danger");
            }
          })
          .catch((error) => {
            if (submitButton) {
              submitButton.disabled = false;
              submitButton.innerHTML = originalButtonText;
            }
            console.error("Помилка надсилання форми:", error);
            displayFlashMessage(
              "Сталася помилка при збереженні даних.",
              "danger"
            );
          });
      });
    }
    const deleteForm = paneElement.querySelector("form.form-delete-entry");
    if (deleteForm) {
      deleteForm.addEventListener("submit", function (e) {
        e.preventDefault();
        const entryIdToDelete = this.action.split("/").pop();
        const modalElement = document.getElementById(
          `deleteEntryModal-${entryIdToDelete}`
        );
        const modalInstance = modalElement
          ? bootstrap.Modal.getInstance(modalElement)
          : null;

        const submitButton = this.querySelector('button[type="submit"]');
        const originalButtonText = submitButton ? submitButton.innerHTML : null;
        if (submitButton) {
          submitButton.disabled = true;
          submitButton.innerHTML =
            '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Видалення...';
        }

        fetch(this.action, {
          method: "POST",
          headers: { "X-Requested-With": "XMLHttpRequest" },
        })
          .then((response) => response.json())
          .then((data) => {
            if (modalInstance) modalInstance.hide();
            if (submitButton) {
              submitButton.disabled = false;
              submitButton.innerHTML = originalButtonText;
            }
            if (data.success) {
              displayFlashMessage(data.message, "success");
              const itemToRemove = entriesListContainer.querySelector(
                `.entry-item[data-entry-id="${data.entry_id}"]`
              );
              if (itemToRemove) {
                itemToRemove.remove();
              }
              if (
                currentActiveEntryItem &&
                currentActiveEntryItem.dataset.entryId === data.entry_id
              ) {
                showSelectEntryMessage();
                currentActiveEntryItem = null;
              }
              if (
                entriesListContainer.querySelectorAll(".entry-item").length ===
                0
              ) {
                renderEntriesList(
                  [],
                  document.getElementById("searchInputField")
                    ? document.getElementById("searchInputField").value.trim()
                    : ""
                );
              }
            } else {
              displayFlashMessage(data.error || "Помилка видалення.", "danger");
            }
          })
          .catch((error) => {
            if (modalInstance) modalInstance.hide();
            if (submitButton) {
              submitButton.disabled = false;
              submitButton.innerHTML = originalButtonText;
            }
            console.error("Помилка видалення:", error);
            displayFlashMessage("Помилка мережі при видаленні.", "danger");
          });
      });
    }
  }

  function updateEntriesList(entryData, isEffectivelyNew) {
    if (!entriesListContainer) return;

    let listItem = entriesListContainer.querySelector(
      `.entry-item[data-entry-id="${entryData.entry_id}"]`
    );

    if (isEffectivelyNew && !listItem) {
      const noEntriesMessage = entriesListContainer.querySelector(
        "div.list-group-item:not(.entry-item)"
      );
      if (noEntriesMessage) {
        noEntriesMessage.remove();
      }

      const newListItem = document.createElement("a");
      newListItem.href = "#";
      newListItem.className =
        "list-group-item list-group-item-action entry-item";
      newListItem.dataset.entryId = entryData.entry_id;
      newListItem.dataset.viewUrl = entryData.view_url;

      newListItem.innerHTML = `${entryData.site_name || "Без назви"}`;
      entriesListContainer.prepend(newListItem);
    } else if (listItem) {
      listItem.innerHTML = `${entryData.site_name || "Без назви"}`;
      listItem.dataset.viewUrl = entryData.view_url;
    }
  }

  function displayFlashMessage(message, category = "info") {
    const flashContainer = document.querySelector(".flash-messages-container");
    if (!flashContainer) {
      const newFlashContainer = document.createElement("div");
      newFlashContainer.className = "flash-messages-container";
      const mainArea =
        document.querySelector("main[role='main']") || document.body;
      mainArea.parentNode.insertBefore(newFlashContainer, mainArea);
    }
    const actualFlashContainer = document.querySelector(
      ".flash-messages-container"
    );
    if (!actualFlashContainer) {
      console.error("Не вдалося знайти або створити flash-messages-container");
      alert(`${category}: ${message}`);
      return;
    }
    const alertDiv = document.createElement("div");
    alertDiv.className = `alert alert-custom alert-${category}-custom alert-dismissible fade show`;
    alertDiv.setAttribute("role", "alert");
    alertDiv.innerHTML = `${message} <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>`;
    actualFlashContainer.prepend(alertDiv);
    if (category === "success" || category === "info") {
      setTimeout(() => {
        const alertInstance = bootstrap.Alert.getOrCreateInstance(alertDiv);
        if (alertInstance && alertDiv.parentElement) {
          alertInstance.close();
        }
      }, 5000);
    }
  }

  function renderEntriesList(entries, searchTerm = "") {
    if (!entriesListContainer) return;
    entriesListContainer.innerHTML = "";

    if (entries && entries.length > 0) {
      entries.forEach((entry) => {
        const listItem = document.createElement("a");
        listItem.href = "#";
        listItem.className =
          "list-group-item list-group-item-action entry-item";
        listItem.dataset.entryId = entry.entry_id;
        listItem.dataset.viewUrl = entry.view_url;

        listItem.innerHTML = `${entry.site_name || "Без назви"}`;
        entriesListContainer.appendChild(listItem);
      });
    } else {
      let message;
      if (searchTerm) {
        message = "За вашим запитом нічого не знайдено.";
      } else {
        message =
          'У вас ще немає збережених паролів. <br>Натисніть "Додати +", щоб створити перший запис.';
      }
      const noEntriesDiv = document.createElement("div");
      noEntriesDiv.className = "list-group-item";
      noEntriesDiv.innerHTML = message;
      entriesListContainer.appendChild(noEntriesDiv);
    }
  }

  function fetchSortedEntries(sortBy, order, searchTerm = "") {
    showLoadingState(entriesListContainer, true);

    const params = new URLSearchParams({
      sort_by: sortBy,
      order: order,
    });
    if (searchTerm) {
      params.append("search", searchTerm);
    }

    const ajaxUrl =
      typeof dashboardUrls !== "undefined" && dashboardUrls.ajaxGetEntries
        ? dashboardUrls.ajaxGetEntries
        : "/entries/ajax/get_entries";

    fetch(`${ajaxUrl}?${params.toString()}`)
      .then((response) => response.json())
      .then((data) => {
        if (data.success && data.entries) {
          renderEntriesList(data.entries, searchTerm);
          updateSortButtonsUI(data.current_sort_by, data.current_order);
        } else {
          if (entriesListContainer)
            entriesListContainer.innerHTML = `<div class="list-group-item text-danger">${
              data.error || "Помилка завантаження списку."
            }</div>`;
        }
      })
      .catch((error) => {
        console.error("Error fetching sorted/searched entries:", error);
        if (entriesListContainer)
          entriesListContainer.innerHTML =
            '<div class="list-group-item text-danger">Помилка мережі при завантаженні списку.</div>';
      });
  }

  function updateSortButtonsUI(activeSortBy, activeOrder) {
    document.querySelectorAll(".sort-link").forEach((button) => {
      const icon = button.querySelector("i");
      if (button.dataset.sortBy === activeSortBy) {
        button.classList.add("active");
        button.dataset.order = activeOrder;
        if (icon) {
          if (activeSortBy === "site_name") {
            icon.className = `bi bi-sort-alpha-${
              activeOrder === "asc" ? "down" : "down-alt"
            }`;
          } else if (activeSortBy === "date_added") {
            icon.className = `bi bi-calendar-event${
              activeOrder === "asc" ? "-fill" : ""
            }`;
          }
        }
      } else {
        button.classList.remove("active");
        button.dataset.order =
          button.dataset.sortBy === "site_name" ? "asc" : "desc";

        if (icon) {
          if (button.dataset.sortBy === "site_name") {
            icon.className = "bi bi-sort-alpha-down";
          } else if (button.dataset.sortBy === "date_added") {
            icon.className = "bi bi-calendar-event";
          }
        }
      }
    });
  }

  document.querySelectorAll(".sort-link").forEach((button) => {
    button.addEventListener("click", function (event) {
      event.preventDefault();
      const sortBy = this.dataset.sortBy;
      let currentOrderForThisButton = this.dataset.order;
      let nextOrder;

      if (this.classList.contains("active")) {
        nextOrder = currentOrderForThisButton === "asc" ? "desc" : "asc";
      } else {
        nextOrder = sortBy === "site_name" ? "asc" : "desc";
      }

      const searchInputField = document.getElementById("searchInputField");
      const searchTerm = searchInputField ? searchInputField.value.trim() : "";
      fetchSortedEntries(sortBy, nextOrder, searchTerm);
    });
  });

  let debounceTimerSearch;
  const searchInputField = document.getElementById("searchInputField");
  const searchEntriesForm = document.getElementById("searchEntriesForm");

  if (searchInputField) {
    searchInputField.addEventListener("input", function () {
      clearTimeout(debounceTimerSearch);
      debounceTimerSearch = setTimeout(() => {
        const searchTerm = this.value.trim();
        const activeSortButton = document.querySelector(".sort-link.active");
        let sortBy = "date_added";
        let order = "desc";

        if (activeSortButton) {
          sortBy = activeSortButton.dataset.sortBy;
          order = activeSortButton.dataset.order;
        }
        fetchSortedEntries(sortBy, order, searchTerm);
      }, 300);
    });
  }

  if (searchEntriesForm) {
    searchEntriesForm.addEventListener("submit", function (event) {
      event.preventDefault();
      clearTimeout(debounceTimerSearch);
      const searchTerm = searchInputField ? searchInputField.value.trim() : "";
      const activeSortButton = document.querySelector(".sort-link.active");
      let sortBy = "date_added";
      let order = "desc";
      if (activeSortButton) {
        sortBy = activeSortButton.dataset.sortBy;
        order = activeSortButton.dataset.order;
      }
      fetchSortedEntries(sortBy, order, searchTerm);
    });
  }

  initializeTooltips(document);
});
