from domain.password_entry import PasswordEntry
from domain import db
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class PasswordRepository:
    def get_by_id(self, entry_id: int, user_id: int) -> PasswordEntry | None:
        """
        Отримує запис пароля за його ID та ID користувача.
        """
        try:
            entry = db.session.query(PasswordEntry).filter_by(entry_id=entry_id, user_id=user_id).first()
            if entry:
                pass
            else:
                pass
            return entry
        except Exception as e:
            logger.error(f"REPOSITORY: Помилка при отриманні запису за ID {entry_id}, user_id {user_id}: {e}", exc_info=True)
            return None

    def get_all_for_user(self, user_id: int) -> list[PasswordEntry]:
        """
        Отримує всі записи паролів для конкретного користувача.
        """
        try:
            entries = db.session.query(PasswordEntry).filter_by(user_id=user_id).all()
            return entries
        except Exception as e:
            logger.error(f"REPOSITORY: Помилка при отриманні всіх записів для user_id {user_id}: {e}", exc_info=True)
            return []

    def add_entry(self, **kwargs) -> PasswordEntry | None:
        """
        Додає новий запис пароля до бази даних.
        Приймає дані для запису як ключові аргументи (kwargs).
        EntryService._prepare_data_for_repo вже має підготувати валідні поля.
        """
        try:
            if 'user_id' not in kwargs:
                logger.error(f"REPOSITORY: Помилка додавання запису - відсутній 'user_id' в даних: {kwargs}")
                raise ValueError("user_id є обов'язковим для додавання запису.")

            kwargs.setdefault('date_added', datetime.utcnow())

            new_entry = PasswordEntry(**kwargs)
            
            db.session.add(new_entry)
            db.session.commit()
            logger.info(f"REPOSITORY: Новий запис успішно додано до БД. ID: {new_entry.entry_id}, Site: {new_entry.site_name}, UserID: {new_entry.user_id}")
            return new_entry
        except ValueError as ve:
            db.session.rollback()
            logger.error(f"REPOSITORY: Помилка значення (ValueError) при додаванні запису: {ve}. Дані: {kwargs}", exc_info=True)
            raise
        except Exception as e:
            db.session.rollback()
            logger.error(f"REPOSITORY: Загальна помилка при додаванні запису до БД. Дані: {kwargs}. Помилка: {e}", exc_info=True)
            raise

    def update_entry(self, entry_model: PasswordEntry, **kwargs) -> PasswordEntry | None:
        """
        Оновлює дані існуючого запису пароля.
        kwargs можуть містити поля для оновлення.
        Автоматично оновлює поле date_updated.
        """
        try:
            has_changes = False
            for key, value in kwargs.items():
                if hasattr(entry_model, key) and key not in ['entry_id', 'user_id']:
                    if getattr(entry_model, key) != value:
                        setattr(entry_model, key, value)
                        has_changes = True
                elif key in ['entry_id', 'user_id']:
                        logger.warning(f"REPOSITORY: Спроба оновити захищене поле '{key}' для запису ID {entry_model.entry_id} проігноровано.")

            if not has_changes and not kwargs.get('force_update_timestamp', False):
                logger.info(f"REPOSITORY: Немає фактичних змін для оновлення запису ID {entry_model.entry_id}.")
                return entry_model

            if hasattr(entry_model, 'date_updated'):
                entry_model.date_updated = datetime.utcnow()
            
            db.session.commit()
            logger.info(f"REPOSITORY: Запис ID {entry_model.entry_id} успішно оновлено. UserID: {entry_model.user_id}. Змінені поля (можливо): {list(kwargs.keys())}")
            return entry_model
        except Exception as e:
            db.session.rollback()
            logger.error(f"REPOSITORY: Помилка при оновленні запису ID {getattr(entry_model, 'entry_id', 'N/A')}. Дані для оновлення: {kwargs}. Помилка: {e}", exc_info=True)
            raise

    def delete_entry(self, entry_model: PasswordEntry) -> bool:
        """
        Видаляє запис пароля з бази даних.
        """
        try:
            entry_id_for_log = entry_model.entry_id
            user_id_for_log = entry_model.user_id
            db.session.delete(entry_model)
            db.session.commit()
            logger.info(f"REPOSITORY: Запис ID {entry_id_for_log} (UserID: {user_id_for_log}) успішно видалено з БД.")
            return True
        except Exception as e:
            db.session.rollback()
            logger.error(f"REPOSITORY: Помилка при видаленні запису ID {getattr(entry_model, 'entry_id', 'N/A')} (UserID: {getattr(entry_model, 'user_id', 'N/A')}): {e}", exc_info=True)
            return False


    def search_entries_for_user(self, user_id: int, search_term: str) -> list[PasswordEntry]:
        """
        Шукає записи паролів для користувача за ключовим словом.
        """
        try:
            search_query = f"%{search_term}%"
            filters = [PasswordEntry.user_id == user_id]
            search_fields_names = ['site_name', 'login', 'email', 'site_url', 'nickname', 'custom_id']
            
            model_columns = PasswordEntry.__table__.columns.keys()
            or_conditions = []

            for field_name in search_fields_names:
                if field_name in model_columns:
                    or_conditions.append(getattr(PasswordEntry, field_name).ilike(search_query))
            
            if not or_conditions:
                logger.warning(f"REPOSITORY: Немає валідних полів для пошуку за терміном '{search_term}'.")
                return []

            filters.append(db.or_(*or_conditions))
            
            results = db.session.query(PasswordEntry).filter(*filters).order_by(PasswordEntry.date_added.desc()).all()
            return results
        except Exception as e:
            logger.error(f"REPOSITORY: Помилка при пошуку записів для user_id {user_id} (термін: {search_term}): {e}", exc_info=True)
            return []

    def get_all_for_user_sorted(self, user_id: int, sort_by: str = "date_added", ascending: bool = True) -> list[PasswordEntry]:
        """
        Отримує всі записи паролів для користувача, відсортовані за вказаним полем.
        """
        try:
            column_to_sort = getattr(PasswordEntry, sort_by, None)

            if column_to_sort is None:
                logger.warning(f"REPOSITORY: Невірне поле для сортування '{sort_by}' для user_id {user_id}. Використовується 'date_added' DESC.")
                column_to_sort = PasswordEntry.date_added
                query_order = column_to_sort.desc()
            elif ascending:
                query_order = column_to_sort.asc()
            else:
                query_order = column_to_sort.desc()
            
            entries = db.session.query(PasswordEntry).filter_by(user_id=user_id).order_by(query_order).all()
            return entries
        except Exception as e:
            logger.error(f"REPOSITORY: Помилка при отриманні відсортованих записів для user_id {user_id} (sort_by: {sort_by}): {e}", exc_info=True)
            return []