from repositories.password_repository import PasswordRepository
from utilities.encryption_util import EncryptionUtility
from domain.password_entry import PasswordEntry
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class EntryService:
    def __init__(self, password_repository: PasswordRepository, encryption_utility: EncryptionUtility):
        self.password_repository = password_repository
        self.encryption_utility = encryption_utility

    def _prepare_data_for_repo(self, input_data: dict, for_update: bool = False) -> dict:
        prepared_data = input_data.copy()
        
        if 'plain_password' in prepared_data:
            plain_password_value = prepared_data.pop('plain_password')
            if plain_password_value:
                encrypted = self.encryption_utility.encrypt(plain_password_value)
                if encrypted is None:
                    logger.error("ENTRY_SERVICE: Помилка шифрування основного пароля. EncryptionUtility повернув None.")
                    raise ValueError("Помилка шифрування пароля.")
                prepared_data['enc_password'] = encrypted
            elif for_update:
                pass
        
        fields_to_encrypt_map = {
            'secret_word_plain': 'secret_word',
            'password_hint_plain': 'password_hint',
            'old_password_plain': 'old_password'
        }

        for plain_key, encrypted_key in fields_to_encrypt_map.items():
            if plain_key in prepared_data:
                value_to_encrypt = prepared_data.pop(plain_key)
                if value_to_encrypt:
                    encrypted_field_value = self.encryption_utility.encrypt(str(value_to_encrypt))
                    if encrypted_field_value is None:
                        logger.warning(f"ENTRY_SERVICE: Не вдалося зашифрувати поле '{plain_key}'. Встановлено NULL.")
                        prepared_data[encrypted_key] = None
                    else:
                        prepared_data[encrypted_key] = encrypted_field_value
                else:
                    prepared_data[encrypted_key] = None

        final_data = {}
        try:
            allowed_model_fields = PasswordEntry.__table__.columns.keys()
        except AttributeError:
            logger.critical("ENTRY_SERVICE: Не вдалося отримати список стовпців з PasswordEntry.", exc_info=True)
            raise RuntimeError("Помилка конфігурації моделі PasswordEntry.")

        for key, value in prepared_data.items():
            if key in allowed_model_fields:
                if for_update and key in ['entry_id', 'user_id', 'date_added']:
                    continue
                final_data[key] = value
        
        if for_update and final_data:
            final_data['date_updated'] = datetime.utcnow()

        return final_data

    def add_entry(self, user_id: int, **kwargs) -> tuple[PasswordEntry | None, str | None]:
        if not kwargs.get('site_name') or not kwargs.get('login') or not kwargs.get('plain_password'):
            logger.warning(f"ENTRY_SERVICE (add): Відсутні обов'язкові поля для user_id {user_id}.")
            return None, "Назва сайту, логін та пароль є обов'язковими."
        
        try:
            data_for_repo = self._prepare_data_for_repo(kwargs, for_update=False)
            data_for_repo['user_id'] = user_id
            
            new_entry = self.password_repository.add_entry(**data_for_repo)
            if new_entry:
                logger.info(f"ENTRY_SERVICE (add): Запис ID {new_entry.entry_id} успішно додано для user_id {user_id}, site: {new_entry.site_name}")
                return new_entry, "Запис успішно додано."
            else:
                logger.error(f"ENTRY_SERVICE (add): Репозиторій повернув None без винятку для user_id {user_id}.")
                return None, "Не вдалося створити запис (помилка репозиторію)."
        except ValueError as ve:
            logger.error(f"ENTRY_SERVICE (add): ValueError: {ve} для user_id {user_id}. Дані: {kwargs}", exc_info=True)
            return None, str(ve)
        except Exception as e:
            logger.error(f"ENTRY_SERVICE (add): Непередбачена помилка: {e} для user_id {user_id}. Дані: {kwargs}", exc_info=True)
            return None, "Виникла непередбачена помилка при збереженні запису."


    def get_entry_details(self, entry_id: int, user_id: int) -> dict | None:
        entry_model = self.password_repository.get_by_id(entry_id, user_id)
        if not entry_model:
            logger.warning(f"ENTRY_SERVICE (get_details): Запис ID {entry_id} не знайдено для user_id {user_id}.")
            return None
        
        details = {}
        try:
            for column in entry_model.__table__.columns:
                details[column.name] = getattr(entry_model, column.name)
        except Exception as e:
            logger.error(f"ENTRY_SERVICE (get_details): Помилка копіювання атрибутів моделі для entry_id {entry_id}: {e}", exc_info=True)
            return None

        if entry_model.enc_password:
            details['password'] = self.encryption_utility.decrypt(entry_model.enc_password)
            if details['password'] is None:
                logger.warning(f"ENTRY_SERVICE (get_details): Не вдалося дешифрувати 'enc_password' для entry_id {entry_id}.")
                details['password'] = ""
        else:
            details['password'] = ""

        encrypted_field_names = ['secret_word', 'password_hint', 'old_password']
        for field_name in encrypted_field_names:
            encrypted_value = getattr(entry_model, field_name, None)
            if encrypted_value:
                decrypted_value = self.encryption_utility.decrypt(encrypted_value)
                details[field_name] = decrypted_value if decrypted_value is not None else ""
                if decrypted_value is None:
                    logger.warning(f"ENTRY_SERVICE (get_details): Не вдалося дешифрувати поле '{field_name}' для entry_id {entry_id}.")
            else:
                details[field_name] = ""

        if details.get('date_added') and isinstance(details['date_added'], datetime):
            details['date_added'] = details['date_added'].isoformat()
        if details.get('date_updated') and isinstance(details['date_updated'], datetime):
            details['date_updated'] = details['date_updated'].isoformat()
        
        details.pop('enc_password', None)
            
        return details


    def update_entry_details(self, entry_id: int, user_id: int, **kwargs) -> tuple[PasswordEntry | None, str | None]:
        entry_model = self.password_repository.get_by_id(entry_id, user_id)
        if not entry_model:
            logger.warning(f"ENTRY_SERVICE (update): Запис ID {entry_id} не знайдено для user_id {user_id}.")
            return None, "Запис не знайдено або у вас немає доступу."

        try:
            data_for_repo = self._prepare_data_for_repo(kwargs, for_update=True)
            
            if not data_for_repo:
                logger.info(f"ENTRY_SERVICE (update): Немає валідних даних для оновлення ID {entry_id}, user_id {user_id}. Надані дані: {kwargs}")
                return entry_model, "Жодних змін не було застосовано, оскільки не надано валідних даних для оновлення."
            
            updated_entry = self.password_repository.update_entry(entry_model, **data_for_repo)
            if updated_entry:
                logger.info(f"ENTRY_SERVICE (update): Запис ID {entry_id} успішно оновлено для user_id {user_id}. Оновлені поля: {list(data_for_repo.keys())}")
                return updated_entry, "Запис успішно оновлено."
            else:
                logger.error(f"ENTRY_SERVICE (update): Репозиторій повернув None без винятку для ID {entry_id}, user_id {user_id}.")
                return None, "Помилка оновлення запису на рівні сховища."
        except ValueError as ve:
            logger.error(f"ENTRY_SERVICE (update): ValueError: {ve} для ID {entry_id}, user_id {user_id}. Дані: {kwargs}", exc_info=True)
            return None, str(ve)
        except Exception as e:
            logger.error(f"ENTRY_SERVICE (update): Непередбачена помилка: {e} для ID {entry_id}, user_id {user_id}. Дані: {kwargs}", exc_info=True)
            return None, "Виникла непередбачена помилка при оновленні запису."

    def delete_entry_item(self, entry_id: int, user_id: int) -> tuple[bool, str | None]:
        entry_model = self.password_repository.get_by_id(entry_id, user_id)
        if not entry_model:
            logger.warning(f"ENTRY_SERVICE (delete): Запис ID {entry_id} не знайдено для user_id {user_id}.")
            return False, "Запис не знайдено або у вас немає доступу."
        try:
            site_name_for_log = entry_model.site_name
            success = self.password_repository.delete_entry(entry_model)
            if success:
                logger.info(f"ENTRY_SERVICE (delete): Запис ID {entry_id} (сайт: '{site_name_for_log}') успішно видалено для user_id {user_id}.")
                return True, "Запис успішно видалено."
            else:
                logger.error(f"ENTRY_SERVICE (delete): Репозиторій повернув помилку (False) при видаленні ID {entry_id} для user_id {user_id}.")
                return False, "Помилка при видаленні запису на рівні сховища."
        except Exception as e:
            logger.error(f"ENTRY_SERVICE (delete): Непередбачена помилка: {e} для ID {entry_id}, user_id {user_id}", exc_info=True)
            return False, "Виникла помилка при видаленні запису."

    def get_all_entries_for_user(self, user_id: int, sort_by: str = "date_added", ascending: bool = True) -> list[dict]:
        try:
            entries_models = self.password_repository.get_all_for_user_sorted(user_id, sort_by, ascending)
            entries_list = []
            for entry_model in entries_models:
                entry_dict = {
                    "entry_id": entry_model.entry_id,
                    "site_name": entry_model.site_name,
                    "login": entry_model.login,
                    "email": entry_model.email,
                    "date_added": entry_model.date_added.isoformat() if entry_model.date_added else None,
                }
                entries_list.append(entry_dict)
            return entries_list
        except Exception as e:
            logger.error(f"ENTRY_SERVICE (get_all_ui): Помилка: {e} для user_id {user_id}", exc_info=True)
            return []

    def search_user_entries(self, user_id: int, search_term: str) -> list[dict]:
        try:
            entries_models = self.password_repository.search_entries_for_user(user_id, search_term)
            entries_list = []
            for entry_model in entries_models:
                entry_dict = {
                    "entry_id": entry_model.entry_id,
                    "site_name": entry_model.site_name,
                    "login": entry_model.login,
                    "email": entry_model.email,
                    "date_added": entry_model.date_added.isoformat() if entry_model.date_added else None,
                }
                entries_list.append(entry_dict)
            return entries_list
        except Exception as e:
            logger.error(f"ENTRY_SERVICE (search_ui): Помилка: {e} для user_id {user_id}, термін '{search_term}'", exc_info=True)
            return []

    def get_all_entries_for_export(self, user_id: int) -> list[dict]:
        """
        Отримує всі записи користувача з дешифрованими паролями та іншими полями
        для експорту.
        """
        try:
            entries_models = self.password_repository.get_all_for_user(user_id)
            export_list = []
            for entry_model in entries_models:
                details = self.get_entry_details(entry_model.entry_id, user_id)
                if details:
                    export_list.append(details)
                else:
                    logger.warning(f"ENTRY_SERVICE (export): Не вдалося отримати/дешифрувати деталі для запису ID {entry_model.entry_id} під час експорту для user_id {user_id}.")

            logger.info(f"ENTRY_SERVICE (export): Підготовлено {len(export_list)} записів для експорту для user_id {user_id}.")
            return export_list
        except Exception as e:
            logger.error(f"ENTRY_SERVICE (export): Помилка при підготовці даних для експорту для user_id {user_id}: {e}", exc_info=True)
            return []