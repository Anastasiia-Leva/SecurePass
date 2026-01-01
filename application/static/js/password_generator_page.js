document.addEventListener("DOMContentLoaded", function () {
  const complexityButtons = document.querySelectorAll(
    ".complexity-options .btn[data-complexity]"
  );
  const criteriaDisplay = document.getElementById("criteriaDisplay");
  const generateBtnPage = document.getElementById("generateBtnPage");
  const generatedPasswordFieldPage = document.getElementById(
    "generatedPasswordPage"
  );
  const copyPasswordBtnPage = document.getElementById("copyPasswordBtnPage");

  const passwordLengthInput = document.getElementById("passwordLength");
  const pinLengthInput = document.getElementById("pinLength");
  const passphraseWordsInput = document.getElementById("passphraseWords");

  const passwordLengthContainer = document.getElementById(
    "passwordLengthContainer"
  );
  const pinLengthContainer = document.getElementById("lengthOptionContainer");
  const passphraseWordsContainer = document.getElementById(
    "passphraseWordsContainer"
  );

  const passwordLengthError = document.getElementById("passwordLengthError");
  const pinLengthError = document.getElementById("pinLengthError");
  const passphraseWordsError = document.getElementById("passphraseWordsError");

  let currentPageComplexity = "strong";

  const presetConfigs = {
    easy: {
      minLen: 8,
      defaultLen: 8,
      maxLen: 50,
      inputId: "passwordLength",
      criteria: "Складається з малих літер та цифр.\nДовжина від 8 символів. ",
    },
    medium: {
      minLen: 12,
      defaultLen: 12,
      maxLen: 50,
      inputId: "passwordLength",
      criteria:
        "Складається з великих та малих літер, цифр.\nДовжина від 12 символів.",
    },
    strong: {
      minLen: 16,
      defaultLen: 16,
      maxLen: 50,
      inputId: "passwordLength",
      criteria:
        "Складається з великих та малих літер, цифр та спецсимволів.\nДовжина від 16 символів.",
    },
    passphrase: {
      minLen: 3,
      defaultLen: 4,
      maxLen: 8,
      inputId: "passphraseWords",
      criteria:
        "Складається з випадкових слів, розділених дефісом.\nВІд 3 слів.",
    },
    pin: {
      minLen: 4,
      defaultLen: 4,
      maxLen: 10,
      inputId: "pinLength",
      criteria: "Складається тільки з цифр.\nДовжина від 4 цифр.",
    },
  };

  function getElementsForPreset(presetKey) {
    const config = presetConfigs[presetKey];
    if (!config) return null;

    let inputEl, containerEl, errorEl;

    if (presetKey === "pin") {
      inputEl = pinLengthInput;
      containerEl = pinLengthContainer;
      errorEl = pinLengthError;
    } else if (presetKey === "passphrase") {
      inputEl = passphraseWordsInput;
      containerEl = passphraseWordsContainer;
      errorEl = passphraseWordsError;
    } else {
      inputEl = passwordLengthInput;
      containerEl = passwordLengthContainer;
      errorEl = passwordLengthError;
    }
    return { config, inputEl, containerEl, errorEl };
  }

  function displayError(errorElement, inputElement, message) {
    if (errorElement) {
      errorElement.textContent = message;
      errorElement.style.display = "block";
    }
    if (inputElement) {
      inputElement.classList.add("is-invalid");
    }
  }

  function clearError(errorElement, inputElement) {
    if (errorElement) {
      errorElement.textContent = "";
      errorElement.style.display = "none";
    }
    if (inputElement) {
      inputElement.classList.remove("is-invalid");
    }
  }

  function updatePageGeneratorUI(selectedButton) {
    if (!selectedButton) return;

    complexityButtons.forEach((btn) =>
      btn.classList.remove("active-complexity")
    );
    selectedButton.classList.add("active-complexity");
    currentPageComplexity = selectedButton.dataset.complexity;

    const elements = getElementsForPreset(currentPageComplexity);
    if (!elements) return;

    const { config, inputEl, containerEl, errorEl } = elements;

    if (criteriaDisplay && config) {
      criteriaDisplay.innerHTML = config.criteria.replace(/\n/g, "<br>");
    } else if (criteriaDisplay) {
      criteriaDisplay.textContent = "Оберіть рівень складності.";
    }

    if (passwordLengthContainer) passwordLengthContainer.style.display = "none";
    if (pinLengthContainer) pinLengthContainer.style.display = "none";
    if (passphraseWordsContainer)
      passphraseWordsContainer.style.display = "none";

    if (passwordLengthInput && passwordLengthError)
      clearError(passwordLengthError, passwordLengthInput);
    if (pinLengthInput && pinLengthError)
      clearError(pinLengthError, pinLengthInput);
    if (passphraseWordsInput && passphraseWordsError)
      clearError(passphraseWordsError, passphraseWordsInput);

    if (containerEl) {
      containerEl.style.display = "block";
    }

    if (inputEl && config) {
      inputEl.min = config.minLen;
      inputEl.max = config.maxLen;
      inputEl.value = config.defaultLen;
      clearError(errorEl, inputEl);
    }
  }

  if (complexityButtons.length > 0) {
    complexityButtons.forEach((button) => {
      button.addEventListener("click", function () {
        updatePageGeneratorUI(this);
      });
    });

    let initiallyActiveButton = document.querySelector(
      ".complexity-options .btn.active-complexity"
    );
    if (!initiallyActiveButton) {
      initiallyActiveButton = Array.from(complexityButtons).find(
        (btn) => btn.dataset.complexity === "strong"
      );
      if (!initiallyActiveButton && complexityButtons.length > 0) {
        initiallyActiveButton = complexityButtons[0];
      }
    }
    if (initiallyActiveButton) {
      updatePageGeneratorUI(initiallyActiveButton);
    }
  }

  if (generateBtnPage) {
    generateBtnPage.addEventListener("click", async function () {
      if (!generatedPasswordFieldPage) return;

      const elements = getElementsForPreset(currentPageComplexity);
      if (!elements) {
        console.error(
          "Конфігурація для поточного типу складності не знайдена при генерації."
        );
        generatedPasswordFieldPage.value = "";
        generatedPasswordFieldPage.placeholder = "Помилка конфігурації";
        return;
      }
      const { config, inputEl, errorEl } = elements;

      if (errorEl && inputEl) clearError(errorEl, inputEl);
      generatedPasswordFieldPage.value = "Генерація...";
      generatedPasswordFieldPage.classList.remove(
        "text-success",
        "text-danger"
      );

      if (!inputEl || !config) {
        displayError(
          passwordLengthError,
          passwordLengthInput,
          "Помилка внутрішньої конфігурації."
        );
        generatedPasswordFieldPage.value = "";
        return;
      }

      const lengthValue = parseInt(inputEl.value, 10);

      if (
        isNaN(lengthValue) ||
        lengthValue < config.minLen ||
        lengthValue > config.maxLen
      ) {
        const unit =
          currentPageComplexity === "passphrase" ? "слів" : "символів";
        const message = `Для '${currentPageComplexity}' кількість повинна бути від ${config.minLen} до ${config.maxLen} ${unit}. Ви вказали: ${inputEl.value}.`;
        displayError(errorEl, inputEl, message);
        generatedPasswordFieldPage.value = "";
        generatedPasswordFieldPage.placeholder = "Помилка вводу";
        return;
      }

      let url =
        typeof GENERATE_PASSWORD_API_URL !== "undefined"
          ? GENERATE_PASSWORD_API_URL
          : "/entries/api/generate-password";

      const params = new URLSearchParams();
      params.append("type", currentPageComplexity);

      if (currentPageComplexity === "passphrase") {
        params.append("words", lengthValue);
      } else {
        params.append("length", lengthValue);
      }

      try {
        const response = await fetch(`${url}?${params.toString()}`);
        const data = await response.json();

        if (response.ok && data.success && data.password) {
          generatedPasswordFieldPage.value = data.password;
          generatedPasswordFieldPage.classList.remove("text-danger");
          generatedPasswordFieldPage.classList.add("text-success");
        } else {
          generatedPasswordFieldPage.value = "";
          generatedPasswordFieldPage.placeholder = "Не вдалося згенерувати";
          generatedPasswordFieldPage.classList.add("text-danger");
          displayError(
            errorEl,
            inputEl,
            data.error || "Помилка генерації на сервері."
          );
        }
      } catch (error) {
        console.error("Error generating password via API:", error);
        generatedPasswordFieldPage.value = "";
        generatedPasswordFieldPage.placeholder = "Помилка зв'язку";
        generatedPasswordFieldPage.classList.add("text-danger");
        const targetErrorEl = errorEl || passwordLengthError;
        const targetInputElement = inputEl || passwordLengthInput;
        displayError(
          targetErrorEl,
          targetInputElement,
          `Помилка зв'язку або обробки. Спробуйте ще раз.`
        );
      }
    });
  }

  if (copyPasswordBtnPage) {
    let tooltipInstance = null;
    if (typeof bootstrap !== "undefined" && bootstrap.Tooltip) {
      tooltipInstance = new bootstrap.Tooltip(copyPasswordBtnPage);
    }

    copyPasswordBtnPage.addEventListener("click", function () {
      if (generatedPasswordFieldPage && generatedPasswordFieldPage.value) {
        navigator.clipboard
          .writeText(generatedPasswordFieldPage.value)
          .then(() => {
            const icon = copyPasswordBtnPage.querySelector("i");
            const originalTitle =
              copyPasswordBtnPage.getAttribute("data-bs-original-title") ||
              copyPasswordBtnPage.title;

            if (icon) {
              icon.classList.remove("bi-clipboard-check");
              icon.classList.add("bi-check-lg");
            }

            copyPasswordBtnPage.setAttribute(
              "data-bs-original-title",
              "Скопійовано!"
            );
            if (tooltipInstance) {
              tooltipInstance.show();
            } else {
              copyPasswordBtnPage.title = "Скопійовано!";
            }

            setTimeout(() => {
              if (icon) {
                icon.classList.remove("bi-check-lg");
                icon.classList.add("bi-clipboard-check");
              }
              copyPasswordBtnPage.setAttribute(
                "data-bs-original-title",
                originalTitle || "Копіювати в буфер обміну"
              );
              if (tooltipInstance) {
                tooltipInstance.hide();
              } else {
                copyPasswordBtnPage.title =
                  originalTitle || "Копіювати в буфер обміну";
              }
            }, 2000);
          })
          .catch((err) => {
            console.error("Failed to copy password: ", err);
            const tempAlert = document.createElement("div");
            tempAlert.className =
              "alert alert-custom alert-warning-custom alert-dismissible fade show";
            tempAlert.style.position = "fixed";
            tempAlert.style.top = "20px";
            tempAlert.style.left = "50%";
            tempAlert.style.transform = "translateX(-50%)";
            tempAlert.style.zIndex = "1060";
            tempAlert.setAttribute("role", "alert");
            tempAlert.innerHTML = `Не вдалося скопіювати пароль. <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>`;
            document.body.appendChild(tempAlert);
            if (typeof bootstrap !== "undefined" && bootstrap.Alert) {
              new bootstrap.Alert(tempAlert);
            }
            setTimeout(() => {
              if (typeof bootstrap !== "undefined" && bootstrap.Alert) {
                const alertInstance =
                  bootstrap.Alert.getOrCreateInstance(tempAlert);
                if (alertInstance) alertInstance.close();
              } else if (tempAlert.parentNode) {
                tempAlert.parentNode.removeChild(tempAlert);
              }
            }, 3000);
          });
      }
    });
  }
});
