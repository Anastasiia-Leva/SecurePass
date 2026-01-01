import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from base64 import urlsafe_b64encode, urlsafe_b64decode

class EncryptionUtility:
    def __init__(self, key: bytes):
        """
        Ініціалізує утиліту шифрування з наданим ключем.
        Ключ має бути 32 байти для AES-256.
        ВАЖЛИВО: Безпечне зберігання та управління цим ключем є критичним!
        Зазвичай, цей ключ завантажується зі змінних середовища або конфігураційного файлу.
        """
        if len(key) != 32:
            raise ValueError("Ключ шифрування для AES-256 має бути довжиною 32 байти.")
        self.key = key
        self.backend = default_backend()

    def encrypt(self, plaintext: str) -> str:
        """
        Шифрує наданий текст за допомогою AES-256-CBC.
        Повертає зашифрований текст у форматі base64.
        """
        if not plaintext:
            return ""

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return urlsafe_b64encode(iv + ciphertext).decode('utf-8')

    def decrypt(self, ciphertext_b64: str) -> str | None:
        """
        Дешифрує наданий текст (base64) за допомогою AES-256-CBC.
        Повертає дешифрований текст або None у випадку помилки.
        """
        if not ciphertext_b64:
            return None
        try:
            encrypted_data = urlsafe_b64decode(ciphertext_b64.encode('utf-8'))
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]

            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext_bytes = unpadder.update(padded_plaintext) + unpadder.finalize()
            return plaintext_bytes.decode('utf-8')
        except Exception as e:
            print(f"Помилка дешифрування: {e}")
            return None