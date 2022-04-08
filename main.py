# Отслеживаемые знания:
# 7081 - КЭ. Работа в системе с сертификатом другого УЦ;
# 13277 - Список УЦ, с которыми нельзя работать в продуктах Контура;
# 13348 - Работа с сертификатом физического лица в Экстерне;
# 3824 - ФСС: вопросы, связанные с сертификатом/Карта знаний;
import config
import telebot
import bot
import time
import engine
import logging
import importlib


ADMIN = 467743559
tg_bot = telebot.TeleBot(config.telegram_api_token)


@tg_bot.message_handler(commands=config.__user_commands)
def handling_commands(message):
    """Обработка пользовательских команд"""

    bot.handling_commands(message)


@tg_bot.message_handler(commands=config.__admin_commands)
def handling_admin_commands(message):
    """Обработка администраторских команд"""

    bot.handling_admin_commands(message)


@tg_bot.message_handler(commands=["update"])
def reload(message):
    """Повторный импорт зависимых библиотек"""

    if message.chat.id == ADMIN:
        importlib.reload(config)
        importlib.reload(engine)
        importlib.reload(bot)
        tg_bot.send_message(ADMIN, "Modules reloaded.")
        logger.info(f"Rerun bot version {bot.__version__}")


@tg_bot.message_handler(content_types=["document"])
def handling_documents(message):
    """Обработка документов"""

    bot.handling_documents(message)


@tg_bot.message_handler(content_types=["text", "audio", "photo", "sticker", "video",
                                       "video_note", "voice", "location", "contact"])
def handling_other(message):
    """Обработка остальных типов данных"""

    bot.handling_other(message)


if __name__ == "__main__":
    logger = logging.getLogger()
    logging.basicConfig(filename="./CertParsingBot.log", filemode="w",
                        format="%(asctime)s | %(levelname)s | %(message)s", datefmt="%d.%m.%Y %H:%M:%S")
    logger.setLevel(logging.INFO)
    logger.info(f"Start bot version {bot.__version__}")
    print("Ok. Let's go")
    while True:
        try:
            tg_bot.skip_pending = True
            tg_bot.polling(none_stop=True)
        except Exception as exc:
            # noinspection PyBroadException
            try:
                tg_bot.send_message(ADMIN, "Something wrong. Pause 5 sec. See /get_logs")
            except Exception:
                pass
            logger.critical(exc)
            time.sleep(5)
