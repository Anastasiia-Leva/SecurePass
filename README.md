# SecurePass – Secure Password Manager

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-green?logo=flask)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Security](https://img.shields.io/badge/Focus-Security-red)

**SecurePass** is a web-based password management application developed as a Bachelor's Thesis project. It demonstrates the implementation of **Clean Architecture (Domain-Driven Design)** principles and industry-standard cryptographic protocols.

⚠️ *Note: The application interface is localized in Ukrainian, while the codebase and documentation follow English technical standards.*

## 🚀 Key Features
* **AES-256-GCM Encryption:** Data is encrypted using the `cryptography` library before storage.
* **Secure Authentication:**
  * **Scrypt** hashing for master passwords (resistant to brute-force).
  * **Google OAuth 2.0** integration.
  * **Two-Factor Authentication (2FA)** via TOTP (Google Authenticator).
* **Clean Architecture:** Strict separation of `Domain`, `Services`, and `Repositories`.
* **Password Generator:** Cryptographically strong random password creation.
* **Automated Security Updates:** Integrated GitHub Dependabot for real-time monitoring and patching of library vulnerabilities (e.g., Authlib, cryptography).
  
## 🛠 Tech Stack
* **Backend:** Python 3.12, Flask 3.0, SQLAlchemy
* **Database:** MySQL 8.0
* **Security:** `cryptography`, `authlib`, `pyotp`, `qrcode`
* **Frontend:** HTML5, CSS3, Bootstrap 5

## 🏗 Project Structure
The project follows a layered architecture to ensure scalability and testability:
* `domain/` — Core business entities (`User`, `PasswordEntry`). No external dependencies.
* `services/` — Business logic (Encryption flows, Auth handling).
* `repositories/` — Data access layer (Database interactions).
* `application/` — Web layer (Routes, Forms, Decorators).
* `external/` — Adapters for third-party services (Google, Email).

## ⚙️ Installation & Setup

1. **Clone the repository**
   ```bash
   git clone [https://github.com/Anastasiia-Leva/SecurePass.git](https://github.com/Anastasiia-Leva/SecurePass.git)
   cd SecurePass

2. **Set up Virtual Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt

4. **Configuration**
   Rename `.env.example` to `.env` and update your database credentials inside it:
   ```ini
   # Example inside .env file:
   DATABASE_URL=mysql+pymysql://user:password@localhost/securepass_db
   SECRET_KEY=your_secret_key

5. **Run the Application**
   ```bash
   python run.py


Author: Anastasiia Leva


