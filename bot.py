import telebot
import engine
import time
import os
import traceback
import re
import logging
import sqlite3
import config
from datetime import datetime
from telebot.types import InputMediaPhoto, ReplyKeyboardMarkup, ReplyKeyboardRemove


ADMIN = 467743559
# TABLE stat (userid, username, date, document, inn_kpp, time, result)
# TABLE settings (userid PRIMARY KEY, username, disableinn, showsnils, thumbprint)
bot = telebot.TeleBot(config.telegram_api_token)
timer = time.time()
statistics_database = sqlite3.connect("statistics.sqlite", check_same_thread=False)
statistics_cursor = statistics_database.cursor()
settings_database = sqlite3.connect("settings.sqlite", check_same_thread=False)
settings_cursor = settings_database.cursor()
logger = logging.getLogger()
__version__ = "1.5.7"
__author__ = "Fedor Kuznetsov"


def change_settings(user: int, name: str, index: int):
    """Замена параметра в базе с настройками. 0 - ИНН, 1 - СНИЛС, 2 - Отпечаток"""

    request = f"SELECT {('disableinn', 'showsnils', 'thumbprint')[index]} FROM settings WHERE userid=?"
    value = list(settings_cursor.execute(request, (user,)))[0][0]
    logger.info(f"{name} change setting {('INN', 'SNILS', 'thumbprint')[index]} to {not bool(value)}")
    request = f"UPDATE settings SET {('disableinn', 'showsnils', 'thumbprint')[index]}=? WHERE userid=?"
    settings_cursor.execute(request, (not value, user))
    settings_database.commit()


def create_keyboard(user: int):
    """Создание уникальной клавиатуры для настроек"""

    sql = settings_cursor.execute("SELECT disableinn, showsnils, thumbprint FROM settings WHERE userid=?", (user,))
    inn, snils, thumbprint = next(sql)
    first_button = ("Отключить проверку ИНН", "Включить проверку ИНН")[inn]
    second_button = ("Показывать СНИЛС", "Скрывать СНИЛС")[snils]
    third_button = ("Показывать отпечаток", "Скрывать отпечаток")[thumbprint]
    keyboard = ReplyKeyboardMarkup(resize_keyboard=True)
    keyboard.row(first_button, second_button)
    keyboard.row(third_button)
    return keyboard


def send_message_to_admin(text):
    """Отправка сообщения админу"""

    bot.send_message(ADMIN, text)


def send_file_to_admin(filename: str, caption: str = None, self_message: bool = False, delete: bool = True):
    """Отправка файла админу
    caption - Подпись к файлу
    self_message - Сообщение от админа
    delete - дальнейшее удаление файла"""

    try:
        if not self_message:
            with open(filename, "rb") as file:
                bot.send_document(ADMIN, file, caption=caption, timeout=10)
        if delete:
            os.remove(filename)
    except FileNotFoundError:
        logger.error(f"File {filename} not found while opening or deleting")


def handling_other(message):
    """Обработка всего лишнего, что не должен обрабатывать бот"""

    if message.content_type == "text":
        text = message.text
        service_text = ("Отключить проверку ИНН", "Включить проверку ИНН",
                        "Показывать СНИЛС", "Скрывать СНИЛС",
                        "Показывать отпечаток", "Скрывать отпечаток")
        reply_text = ("Проверка ИНН отключена.\nДля включения - /settings",
                      "Проверка ИНН включена.\nДля отключения - /settings",
                      "Показ СНИЛС включен.\nДля отключения - /settings",
                      "Показ СНИЛС отключен.\nДля включения - /settings",
                      "Показ отпечатка включен.\nДля отключения - /settings",
                      "Показ отпечатка отключен.\nДля включения - /settings")
        if text in service_text:
            bot.send_message(message.chat.id, reply_text[service_text.index(text)], reply_markup=ReplyKeyboardRemove())
            idx = 0 if text in service_text[:2] else (1 if text in service_text[2:4] else 2)
            change_settings(message.chat.id, message.chat.username, idx)
        else:
            logger.info(f"{message.chat.id} | {message.chat.username} | Sent content - {message.content_type}")
            bot.forward_message(ADMIN, message.chat.id, message.message_id)
    else:
        logger.info(f"{message.chat.id} | {message.chat.username} | Sent content - {message.content_type}")
        bot.forward_message(ADMIN, message.chat.id, message.message_id)


def handling_commands(message):
    """Обработка пользовательских команд"""

    logger.info(f"{message.chat.id} | {message.chat.username} | Sent command {message.text}")
    if message.text in ("/help", "/start"):
        with open("_dispatch.png", "rb") as dispatch, \
             open("_error.png", "rb") as error, \
             open("_success.png", "rb") as success, \
             open("_warning.png", "rb") as warning:
            bot.send_media_group(message.chat.id, [InputMediaPhoto(dispatch, caption=config.CAPTIONS["help"]),
                                                   InputMediaPhoto(error),
                                                   InputMediaPhoto(success),
                                                   InputMediaPhoto(warning)])
    elif message.text == "/info":
        bot.send_message(message.chat.id, config.CAPTIONS["info"],
                         parse_mode="MarkdownV2", disable_web_page_preview=True)
    elif message.text == "/checks":
        bot.send_message(message.chat.id, config.CAPTIONS["checks"])
    elif message.text == "/settings":
        try:
            next(settings_cursor.execute("SELECT * FROM settings WHERE userid=?", (message.chat.id,)))
        except StopIteration:
            # Если пользователя нет в БД с настройками. Ему отправляется 2 сообщения и он добавляется в БД
            with open("_settings.png", "rb") as settings:
                bot.send_photo(message.chat.id, settings, caption=config.CAPTIONS["settings"])
                settings_cursor.execute("INSERT INTO settings VALUES(?, ?, ?, ?, ?)",
                                        (message.chat.id, message.chat.username, False, False, True))
                settings_database.commit()
        finally:
            bot.send_message(message.chat.id, "Выбери интересующую настройку.",
                             reply_markup=create_keyboard(message.chat.id))


def handling_admin_commands(message):
    """Обработка администраторских команд"""

    global timer
    if message.chat.id == ADMIN:
        if message.text == "/get_stat":
            send_file_to_admin("statistics.sqlite", delete=False)
        elif message.text == "/get_settings":
            send_file_to_admin("settings.sqlite", delete=False)
        elif message.text == "/get_logs":
            send_file_to_admin("CertParsingBot.log", delete=False)
        elif message.text == "/update_fss":
            engine.update_fss()
            send_message_to_admin(f"{len(engine.FSS)} CA downloaded.")
            timer = time.time()


def handling_documents(message):
    """Обработка документов"""

    global timer
    # Повторный запрос раз в неделю. 7 дней = 604800 секунд
    if time.time() - timer > 604800:
        timer = time.time()
        logger.info(f"Update FSS list")
        engine.update_fss()

    def save_file():
        """Сохранение пользовательского файла из api.telegram.org"""

        filename = message.document.file_name
        logger.info(f"{message.chat.id} | {message.chat.username} | Sent document {filename} | \
Caption '{message.caption}' | Size {message.document.file_size} | Msg id - {message.id}")
        downloaded_file = bot.download_file(bot.get_file(message.document.file_id).file_path)
        # Для замены исходников через бота. Чтобы не ходить на виртуалку ради каждого изменения
        if message.caption == "/replace" and message.chat.id == ADMIN:
            if os.path.exists(filename):
                os.remove(filename)
            with open(filename, "wb") as new_file:
                new_file.write(downloaded_file)
            send_message_to_admin("File replaced.")
            return
        with open(f"./Сертификаты/{filename}", "wb") as new_file:
            new_file.write(downloaded_file)
        return f"./Сертификаты/{filename}"

    def parse_caption(caption: str):
        """Парсинг подписи к файлу"""

        inn_and_kpp = re.findall(r"\d+", caption or "0000000000")
        if not inn_and_kpp:
            return
        elif len(inn_and_kpp) >= 2:
            inn_caption, kpp_caption = inn_and_kpp[0], inn_and_kpp[1]
        else:
            inn_caption = inn_and_kpp[0]
            if any((len(inn_caption) == 10,
                    len(inn_caption) == 11 and inn_caption[:1] == "0",
                    len(inn_caption) == 12 and inn_caption[:2] == "00")):
                kpp_caption = ""
            else:
                kpp_caption = inn_caption[:4] + "00000"
        return inn_caption, kpp_caption

    def add_parameters(certificate: engine.Certificate, inn_parameter: str, kpp_parameter: str, user) -> list:
        """Добавление дополнительных параметров к ответному сообщению"""

        # Запрос к БД с настройками для определения дальнейшего показа СНИЛС/Отпечатка
        try:
            sql1 = settings_cursor.execute("SELECT showsnils FROM settings WHERE userid=?", (user,))
            show_snils = next(sql1)[0]
        except StopIteration:
            show_snils = False
        try:
            sql2 = settings_cursor.execute("SELECT thumbprint FROM settings WHERE userid=?", (user,))
            show_thumbprint = next(sql2)[0]
        except StopIteration:
            show_thumbprint = True
        if certificate.diadoc.success_request:
            tp_param = f"Отпечаток — `{certificate.diadoc.Thumbprint}`." * show_thumbprint
        else:
            tp_param = f"Отпечаток — `{certificate.get_thumbprint().upper()}`." * show_thumbprint
        un_param = create_unstructured_name(certificate, inn_parameter,
                                            kpp_parameter) or f"СНИЛС — `{certificate.snils}`." * show_snils
        # 2 пустые строки, чтобы визуально отделить параметры от результата проверки в ответном сообщении
        return ["", ""] + [parameter for parameter in (tp_param, un_param) if parameter]

    path = save_file()
    if path is None:
        return
    # noinspection PyBroadException
    try:
        start = time.time()
        reply_message = ""
        cert = engine.Certificate(path)
        inn_kpp = parse_caption(message.caption)
        if inn_kpp is None:
            reply_message += "\u26a0 Неверный формат ИНН-КПП. Значение заменено на 0000000000.\n\n"
            inn = "0000000000"
            kpp = ""
        else:
            inn, kpp = inn_kpp
        # cert.pyver = None, если информацию из файла не удалось прочитать
        if not cert.pyver:
            bot.reply_to(message, config.CAPTIONS["incorrect_file"])
            send_file_to_admin(path, f'@{message.chat.username} sent incorrect document.')
            add_record_to_database(message, inn, kpp, 0, "Sent incorrect document")
        else:
            try:
                sql = settings_cursor.execute("SELECT disableinn FROM settings WHERE userid=?", (message.chat.id,))
                inn_setting = next(sql)[0]
            except StopIteration:
                inn_setting = False
            result = check_cert(cert, inn, inn_setting and message.caption is None)
            finish = round(time.time() - start, 2)
            # Если в ответном сообщении будет больше 2 пунктов, они разделяются маркером.
            # Указана длина 3, т.к. ответное сообщение состоит еще из служебной фразы с результатом проверки
            sep = "\n" if len(result[0]) < 3 else "\n• "
            reply_message += sep.join(result[0])
            if result[1] > 0:
                reply_message += "\n".join(add_parameters(cert, inn, kpp, user=message.chat.id))
            reply_message_to_logs = bot.reply_to(message, reply_message.strip(),
                                                 disable_web_page_preview=True, parse_mode="Markdown")
            logger.info(f"Reply to {message.chat.id} | Msg id - {reply_message_to_logs.message_id}")
            send_file_to_admin(path, caption=f"Пользователь — @{message.chat.username}\nИНН-КПП — {inn}-{kpp}\n\
Результат:\n{result[0]}", self_message=message.chat.id == ADMIN)
            add_record_to_database(message, inn, kpp, finish, " ".join(result[0])[2:])
    except UnicodeDecodeError:
        reply_message_to_logs = bot.reply_to(message, config.CAPTIONS["not_cert"])
        logger.error(f"{message.chat.id} | {message.chat.username} | Sent something else, not certificate \
| Msg id - {reply_message_to_logs.message_id}")
        send_file_to_admin(path, f'@{message.chat.username} sent something wrong.')
    except Exception:
        logger.critical(f"{message.chat.id} | {message.chat.username} | {traceback.format_exc()}")
        bot.reply_to(message, config.CAPTIONS["error"])
        send_message_to_admin("Something wrong. See /get_logs.")


def add_record_to_database(message, inn: str, kpp: str, check_time: float, result: str):
    """Добавление записи в базу данных"""

    request = "INSERT INTO stat VALUES(?, ?, ?, ?, ?, ?, ?)"
    statistics_cursor.execute(request, (message.chat.id, message.chat.username, f"{datetime.today():%d.%m.%Y %H:%M}",
                                        message.document.file_name, "-".join((inn, kpp)).strip("-"),
                                        check_time, result))
    statistics_database.commit()


def create_unstructured_name(cert: engine.Certificate, inn: str, kpp: str) -> str:
    """Формирование тройного идентификатора"""

    snils = str(cert.snils).rjust(12, "0")
    unstructured_name = cert.unstructured_name
    if inn.startswith("00"):
        inn = inn[2:]
    if unstructured_name:
        unstructured_name = str(unstructured_name)
        if re.match(r"\d{10,12}-\d{9}-\d{12}", unstructured_name):
            return f"Тройной идентификатор — `{unstructured_name}`."
        elif kpp:
            return f"Тройной идентификатор — `{'-'.join((inn, kpp, snils))}`."
    elif kpp:
        return f"Тройной идентификатор — `{'-'.join((inn, kpp, snils))}`."
    return ""


def check_cert(cert: engine.Certificate, inn: str, disabled: bool) -> (list, int):
    """Проверка всех условий"""

    valid = ("\u274c Сертификат не подходит для работы. Причины:\n",
             "\u26a0 Сертификат подходит для работы. Обрати внимание:\n",
             "\u2705 Сертификат подходит для работы.")
    result = engine.check_all(cert, inn,
                              all_checks=str(cert.issuer_ogrn) not in config.TRUSTED_CA,
                              personal=cert.personal,
                              disabled_inn=disabled)
    if result is None:
        return [config.CAPTIONS["error"]], -1
    elif result[0]:
        return [valid[0]] + list(result[0]), 0
    elif result[1]:
        return [valid[1]] + list(result[1]), 1
    else:
        return [valid[2]], 2
