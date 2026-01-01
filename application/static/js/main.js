
document.addEventListener("DOMContentLoaded", function () {
  const tooltipTriggerList = [].slice.call(
    document.querySelectorAll('[data-bs-toggle="tooltip"]')
  );
  tooltipTriggerList.map(function (tooltipTriggerEl) {
    return new bootstrap.Tooltip(tooltipTriggerEl);
  });

  
  const flashMessages = document.querySelectorAll(
    ".flash-messages-container .alert-custom"
  );
  flashMessages.forEach(function (message) {
    
    if (
      message.classList.contains("alert-success-custom") ||
      message.classList.contains("alert-info-custom")
    ) {
      setTimeout(() => {
        const alertInstance = bootstrap.Alert.getOrCreateInstance(message);
        if (alertInstance) {
          alertInstance.close();
        }
      }, 5000); // 5 секунд
    }
  });
});


function togglePasswordVisibility(inputId, buttonElement) {
  const input = document.getElementById(inputId);
  if (!input) {
    console.warn(
      `Елемент з ID '${inputId}' не знайдено для togglePasswordVisibility`
    );
    return;
  }

  const icon = buttonElement.querySelector("i");
  if (!icon) {
    console.warn(
      `Іконка всередині кнопки не знайдена для togglePasswordVisibility (inputId: ${inputId})`
    );
    return;
  }

  if (input.type === "password") {
    input.type = "text";
    icon.classList.remove("bi-eye-slash");
    icon.classList.add("bi-eye");
    buttonElement.setAttribute("aria-label", "Сховати пароль");
  } else {
    input.type = "password";
    icon.classList.remove("bi-eye");
    icon.classList.add("bi-eye-slash");
    buttonElement.setAttribute("aria-label", "Показати пароль");
  }
}


let inactivityTimer;
function startInactivityTimer(logoutUrl, inactivityTimeoutMinutes = 10) {
  const timeoutMilliseconds = inactivityTimeoutMinutes * 60 * 1000;

  const resetTimer = () => {
    clearTimeout(inactivityTimer);
    inactivityTimer = setTimeout(() => {
      
      window.location.href = logoutUrl;
    }, timeoutMilliseconds);
  };

  
  window.onload = resetTimer;
  document.onmousemove = resetTimer;
  document.onkeypress = resetTimer;
  document.onclick = resetTimer;
  document.onscroll = resetTimer;
  document.onfocus = resetTimer;

  console.log(
    `Таймер бездіяльності встановлено на ${inactivityTimeoutMinutes} хвилин.`
  );
}

