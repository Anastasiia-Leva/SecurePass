document.addEventListener("DOMContentLoaded", function () {
  const autoLogoutSwitch = document.getElementById("autoLogoutSwitch");
  const nightModeSwitch = document.getElementById("nightModeSwitch");

  function saveUserPreference(preferenceName, preferenceValue, switchElement) {
    const initialState = switchElement ? !preferenceValue : null;

    fetch(settingsUrls.updatePreference, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        preference_name: preferenceName,
        preference_value: preferenceValue,
      }),
    })
      .then((response) => {
        if (!response.ok) {
          return response
            .json()
            .then((errData) => {
              throw new Error(
                errData.error || `Помилка сервера: ${response.status}`
              );
            })
            .catch(() => {
              throw new Error(`Помилка сервера: ${response.status}`);
            });
        }
        return response.json();
      })
      .then((data) => {
        if (data.success) {
          displayFlashMessage(
            data.message || "Налаштування оновлено.",
            "success"
          );

          if (preferenceName === "night_mode_enabled") {
            const appLogo = document.getElementById("appLogo");
            if (preferenceValue) {
              document.body.classList.add("night-mode");
              document.body.classList.remove("light-mode");
              if (appLogo && appLogo.dataset.logoLight) {
                appLogo.src = appLogo.dataset.logoLight;
                appLogo.alt = "SecurePass Логотип (для темної теми)";
              }
            } else {
              document.body.classList.add("light-mode");
              document.body.classList.remove("night-mode");
              if (appLogo && appLogo.dataset.logoDark) {
                appLogo.src = appLogo.dataset.logoDark;
                appLogo.alt = "SecurePass Логотип (для світлої теми)";
              }
            }
          }
        } else {
          displayFlashMessage(
            data.error || "Помилка збереження налаштування.",
            "danger"
          );
          if (switchElement && initialState !== null) {
            switchElement.checked = initialState;
          }
        }
      })
      .catch((error) => {
        console.error("Помилка збереження налаштування:", error);
        displayFlashMessage(
          error.message || "Помилка мережі або сервера при збереженні.",
          "danger"
        );
        if (switchElement && initialState !== null) {
          switchElement.checked = initialState;
        }
      });
  }

  if (autoLogoutSwitch) {
    autoLogoutSwitch.addEventListener("change", function () {
      const value = this.checked;
      if (!value) {
        const confirmModalElement = document.getElementById(
          "autoLogoutDisableConfirmModal"
        );
        if (!confirmModalElement) {
          console.error("Modal 'autoLogoutDisableConfirmModal' not found.");
          saveUserPreference("auto_logout_enabled", false, this);
          return;
        }
        const confirmModal = new bootstrap.Modal(confirmModalElement);

        let oldConfirmBtn = document.getElementById(
          "confirmDisableAutoLogoutBtn"
        );
        let newConfirmBtn = oldConfirmBtn.cloneNode(true);
        oldConfirmBtn.parentNode.replaceChild(newConfirmBtn, oldConfirmBtn);

        let oldCancelBtn = document.getElementById(
          "cancelDisableAutoLogoutBtn"
        );
        let newCancelBtn = oldCancelBtn.cloneNode(true);
        oldCancelBtn.parentNode.replaceChild(newCancelBtn, oldCancelBtn);

        const handleConfirm = () => {
          saveUserPreference("auto_logout_enabled", false, this);
          confirmModal.hide();
        };
        const handleCancel = () => {
          this.checked = true;
          confirmModal.hide();
        };

        newConfirmBtn.addEventListener("click", handleConfirm, { once: true });
        newCancelBtn.addEventListener("click", handleCancel, { once: true });

        confirmModal.show();
      } else {
        saveUserPreference("auto_logout_enabled", true, this);
      }
    });
  }

  if (nightModeSwitch) {
    nightModeSwitch.addEventListener("change", function () {
      const isEnabled = this.checked;
      saveUserPreference("night_mode_enabled", isEnabled, this);
    });
  }

  const showChangePasswordFormBtn = document.getElementById(
    "showChangePasswordFormBtn"
  );
  const changePasswordFormContainer = document.getElementById(
    "changePasswordFormContainer"
  );
  const changePasswordForm = document.getElementById("changePasswordForm");
  const changePassword2faForm = document.getElementById(
    "changePassword2faForm"
  );
  const cancelChangePasswordBtn = document.getElementById(
    "cancelChangePasswordBtn"
  );
  const cancel2faChangePasswordBtn = document.getElementById(
    "cancel2faChangePasswordBtn"
  );
  const changePasswordErrorDiv = document.getElementById("changePasswordError");
  const changePassword2faErrorDiv = document.getElementById(
    "changePassword2faError"
  );

  function displayError(div, message) {
    if (div) {
      div.textContent = message;
      div.style.display = "block";
    }
  }
  function clearError(div) {
    if (div) {
      div.textContent = "";
      div.style.display = "none";
    }
  }
  function togglePasswordVisibility(event) {
    const button = event.currentTarget;
    const targetInputId = button.dataset.targetInput;
    const passwordInput = document.getElementById(targetInputId);
    const icon = button.querySelector("i");

    if (passwordInput && icon) {
      if (passwordInput.type === "password") {
        passwordInput.type = "text";
        icon.classList.remove("bi-eye-slash");
        icon.classList.add("bi-eye");
      } else {
        passwordInput.type = "password";
        icon.classList.remove("bi-eye");
        icon.classList.add("bi-eye-slash");
      }
    }
  }
  document.querySelectorAll(".toggle-password-visibility").forEach((button) => {
    button.addEventListener("click", togglePasswordVisibility);
  });

  if (showChangePasswordFormBtn) {
    showChangePasswordFormBtn.addEventListener("click", function () {
      if (changePasswordFormContainer) {
        const isHidden =
          changePasswordFormContainer.style.display === "none" ||
          !changePasswordFormContainer.style.display;
        changePasswordFormContainer.style.display = isHidden ? "block" : "none";
        if (isHidden) {
          if (changePasswordForm) changePasswordForm.style.display = "block";
          if (changePassword2faForm)
            changePassword2faForm.style.display = "none";
          clearError(changePasswordErrorDiv);
          clearError(changePassword2faErrorDiv);
          if (changePasswordForm) changePasswordForm.reset();
          if (changePassword2faForm) changePassword2faForm.reset();
        }
      }
    });
  }

  if (cancelChangePasswordBtn) {
    cancelChangePasswordBtn.addEventListener("click", function () {
      if (changePasswordFormContainer)
        changePasswordFormContainer.style.display = "none";
      if (changePasswordForm) changePasswordForm.reset();
      clearError(changePasswordErrorDiv);
    });
  }
  if (cancel2faChangePasswordBtn) {
    cancel2faChangePasswordBtn.addEventListener("click", function () {
      if (changePasswordForm) changePasswordForm.style.display = "block";
      if (changePassword2faForm) changePassword2faForm.style.display = "none";
      if (changePassword2faForm) changePassword2faForm.reset();
      clearError(changePassword2faErrorDiv);
    });
  }

  if (changePasswordForm) {
    changePasswordForm.addEventListener("submit", function (event) {
      event.preventDefault();
      clearError(changePasswordErrorDiv);
      const currentPasswordEl = document.getElementById("current_password");
      const newPasswordEl = document.getElementById("new_password");
      const confirmNewPasswordEl = document.getElementById(
        "confirm_new_password"
      );
      if (!currentPasswordEl || !newPasswordEl || !confirmNewPasswordEl) {
        return;
      }
      const currentPassword = currentPasswordEl.value;
      const newPassword = newPasswordEl.value;
      const confirmNewPassword = confirmNewPasswordEl.value;
      if (newPassword.length < 8) {
        displayError(
          changePasswordErrorDiv,
          "Новий пароль має містити щонайменше 8 символів."
        );
        return;
      }
      if (newPassword !== confirmNewPassword) {
        displayError(changePasswordErrorDiv, "Нові паролі не співпадають.");
        return;
      }
      if (currentPassword === newPassword) {
        displayError(
          changePasswordErrorDiv,
          "Новий пароль має відрізнятися від поточного."
        );
        return;
      }
      const submitButton = changePasswordForm.querySelector(
        'button[type="submit"]'
      );
      const originalButtonText = submitButton.innerHTML;
      submitButton.disabled = true;
      submitButton.innerHTML =
        '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Обробка...';
      fetch(settingsUrls.requestPasswordChange, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          current_password: currentPassword,
          new_password: newPassword,
        }),
      })
        .then((response) => response.json())
        .then((data) => {
          submitButton.disabled = false;
          submitButton.innerHTML = originalButtonText;
          if (data.success) {
            displayFlashMessage(
              data.message || "Код підтвердження надіслано.",
              "success"
            );
            changePasswordForm.style.display = "none";
            if (changePassword2faForm) {
              changePassword2faForm.style.display = "block";
              const otpInput = document.getElementById(
                "change_password_otp_code"
              );
              if (otpInput) otpInput.focus();
            }
            clearError(changePasswordErrorDiv);
          } else {
            displayError(
              changePasswordErrorDiv,
              data.error || "Помилка запиту зміни пароля."
            );
          }
        })
        .catch((error) => {
          submitButton.disabled = false;
          submitButton.innerHTML = originalButtonText;
          console.error("Error requesting password change:", error);
          displayError(changePasswordErrorDiv, "Помилка мережі або сервера.");
        });
    });
  }

  if (changePassword2faForm) {
    changePassword2faForm.addEventListener("submit", function (event) {
      event.preventDefault();
      clearError(changePassword2faErrorDiv);
      const otpCodeEl = document.getElementById("change_password_otp_code");
      if (!otpCodeEl) {
        displayError(changePassword2faErrorDiv, "Помилка форми.");
        return;
      }
      const otpCode = otpCodeEl.value;
      if (!/^\d{6}$/.test(otpCode)) {
        displayError(changePassword2faErrorDiv, "Код має складатися з 6 цифр.");
        return;
      }
      const submitButton = changePassword2faForm.querySelector(
        'button[type="submit"]'
      );
      const originalButtonText = submitButton.innerHTML;
      submitButton.disabled = true;
      submitButton.innerHTML =
        '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Перевірка...';
      fetch(settingsUrls.confirmPasswordChange, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ otp_code: otpCode }),
      })
        .then((response) => response.json())
        .then((data) => {
          submitButton.disabled = false;
          submitButton.innerHTML = originalButtonText;
          if (data.success) {
            displayFlashMessage(
              data.message || "Майстер-пароль успішно змінено!",
              "success"
            );
            if (changePasswordFormContainer)
              changePasswordFormContainer.style.display = "none";
            if (changePasswordForm) changePasswordForm.reset();
            changePassword2faForm.reset();
          } else {
            displayError(
              changePassword2faErrorDiv,
              data.error || "Помилка підтвердження зміни пароля."
            );
          }
        })
        .catch((error) => {
          submitButton.disabled = false;
          submitButton.innerHTML = originalButtonText;
          console.error("Error confirming password change:", error);
          displayError(
            changePassword2faErrorDiv,
            "Помилка мережі або сервера при підтвердженні."
          );
        });
    });
  }

  const confirmDeleteBtnModal = document.getElementById(
    "confirmDeleteAccountBtn"
  );
  const deleteAccountModalElement =
    document.getElementById("deleteAccountModal");
  let deleteAccountModalInstance = null;
  if (deleteAccountModalElement) {
    deleteAccountModalInstance = bootstrap.Modal.getOrCreateInstance(
      deleteAccountModalElement
    );
  }
  if (confirmDeleteBtnModal) {
    confirmDeleteBtnModal.addEventListener("click", function () {
      const passwordInput = document.getElementById("confirmDeletePassword");
      const password = passwordInput ? passwordInput.value : null;
      const errorDiv = document.getElementById("deleteAccountError");
      clearError(errorDiv);
      if (!password) {
        displayError(
          errorDiv,
          "Будь ласка, введіть ваш пароль для підтвердження."
        );
        return;
      }
      const deleteForm = document.createElement("form");
      deleteForm.method = "POST";
      if (typeof settingsUrls !== "undefined" && settingsUrls.deleteAccount) {
        deleteForm.action = settingsUrls.deleteAccount;
      } else {
        console.error("URL для видалення акаунту не знайдено.");
        displayError(errorDiv, "Помилка конфігурації.");
        return;
      }
      const passwordField = document.createElement("input");
      passwordField.type = "hidden";
      passwordField.name = "password";
      passwordField.value = password;
      deleteForm.appendChild(passwordField);
      const csrfTokenValue =
        typeof csrfToken !== "undefined"
          ? csrfToken
          : settingsUrls.csrfToken || null;
      if (csrfTokenValue) {
        const csrfField = document.createElement("input");
        csrfField.type = "hidden";
        csrfField.name = "csrf_token";
        csrfField.value = csrfTokenValue;
        deleteForm.appendChild(csrfField);
      }
      document.body.appendChild(deleteForm);
      if (deleteAccountModalInstance) {
        deleteAccountModalInstance.hide();
      }
      deleteForm.submit();
    });
  }

  const exportConfirmModalElement =
    document.getElementById("exportConfirmModal");
  const confirmExportCsvBtn = document.getElementById("confirmExportCsvBtn");

  let exportConfirmModalInstance = null;
  if (exportConfirmModalElement) {
    exportConfirmModalInstance = new bootstrap.Modal(exportConfirmModalElement);
  }

  if (confirmExportCsvBtn && exportConfirmModalInstance) {
    confirmExportCsvBtn.addEventListener("click", function () {
      if (settingsUrls && settingsUrls.exportCsv) {
        window.location.href = settingsUrls.exportCsv;
        exportConfirmModalInstance.hide();
      } else {
        console.error(
          "URL для експорту CSV не визначено в settingsUrls.exportCsv"
        );
        displayFlashMessage("Помилка: URL для експорту не знайдено.", "danger");
        exportConfirmModalInstance.hide();
      }
    });
  }

  function displayFlashMessage(message, category = "info", duration = 5000) {
    const container =
      document.querySelector(".flash-messages-container") ||
      (() => {
        const newContainer = document.createElement("div");
        newContainer.className = "flash-messages-container";
        const mainContent =
          document.querySelector(".main-content-area") || document.body;
        mainContent.parentNode.insertBefore(newContainer, mainContent);
        return newContainer;
      })();

    const alertDiv = document.createElement("div");
    alertDiv.className = `alert alert-custom alert-${category}-custom alert-dismissible fade show`;
    alertDiv.setAttribute("role", "alert");
    alertDiv.innerHTML = `${message}<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>`;

    container.insertBefore(alertDiv, container.firstChild);

    if (duration && (category === "success" || category === "info")) {
      setTimeout(() => {
        const alertInstance = bootstrap.Alert.getOrCreateInstance(alertDiv);
        if (alertInstance && alertDiv.parentElement) {
          alertInstance.close();
        }
      }, duration);
    }
  }
});
