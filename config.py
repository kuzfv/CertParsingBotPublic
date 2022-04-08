# https://wiki.skbkontur.ru/pages/viewpage.action?pageId=421505102 - Аккредитованные УЦ;
import os
from datetime import datetime

# Здесь на боевом сервере указан telegram_api_token

__user_commands = ["help", "start", "info", "checks", "settings"]
__admin_commands = ["get_stat", "get_logs", "update_fss", "get_settings"]

ok = ("Будут проверены:", "Квалифицированность сертификата", "Совпадение ИНН из сертификата и ИНН УЗ для ЮЛ",
      "Корректность поля CN для ЮЛ", "Срок действия сертификата", "Статус отзыва сертификата", "Все условия для ФСС",
      'Поле "Политики сертификата"', 'Поле "Использование ключа"', "Отметки ЕГРЮЛ", "Издатель",
      "Наличие аккредитации издателя и дата ее получения", "Срок действия закрытого ключа")
not_ok = ("Не будут проверены:", "Облачность сертификата", "Тест контейнера", "Статус особого контроля в КабУЦ")

# Список недобросовестных УЦ. Множество из значений ОГРН.
# Далее в комментарии указывается наименование УЦ для удобства
NOT_VALID_CA = {"1022502121476",  # ЗАО «Сервер-Центр»
                "1052503122902",  # АО "Атлас-2"
                "1096670000624",  # ООО "Солар"
                "1167232094743",  # ООО "ТУНЦ"
                "1167746807360",  # ООО "МЦСП-ГРУПП"
                "1197746061446",  # ООО УЦ "Столица"
                "1166196092413",  # ООО "Омега"
                "1112310000220",  # ООО "ИТК"
                "1111840008411",  # ООО "ИжТендер"
                }

# Список УЦ, для которых выполняются не все проверки. Множество из значений ОГРН.
# Далее в комментарии указывается наименование УЦ для удобства
TRUSTED_CA = {"1047797019830",  # Федеральное казначейство
              "1047707030513",  # Федеральная налоговая служба
              "1037700013020",  # Центральный банк Российской Федерации
              "1027600787994",  # ООО "Компания "Тензор"
              "1116673008539",  # ООО "Сертум-Про"
              }

# Пользовательские команды и ответы на них. Словарь в формате {"Команда": "Ответ"}
CAPTIONS = {
    # В /help и /start используются изображения _dispatch.png, _error.png, _warning.png, _success.png
    "help": "Загрузи файл сертификата и введи ИНН-КПП учетной записи.\nЕсли при проверке будут найдены ошибки, бот \
покажет их.\nЕсли проверка пройдет без ошибок, дополнительно будут указаны отпечаток сертификата и тройной \
идентификатор.\nЕсли проверка пройдет без ошибок, но будут найдены детали, требующие внимания, это будет указано.",
    # В /info используются текстовые гиперссылки, поэтому добавлены слэши перед спецсимволами
    "info": "• Время обновления списка доверенных УЦ с портала ФСС — 1 неделя\\.\n• Тройной идентификатор будет показан\
 только при введенном ИНН\\-КПП или наличии OIDа, соответствующего шаблону\\.\n• Для ИП — КПП будет указан из первых 4 \
 цифр ИНН \\+ 5 нулей\\.\n• Время сервера для проверок, которые требуют даты, определяется по Гринвичу UTC\\+0\\.\
 \n\n[Описание и история изменений](https://wiki.skbkontur.ru/pages/viewpage.action?pageId=454840261)\n",
    "error": "Во время выполнения проверки произошла ошибка. Возможно, это временная проблема. Попробуй \
проверить файл повторно. Если ошибка повторится, проверь файл вручную.",
    "incorrect_file": "Не удалось извлечь информацию из файла. Проверь формат файла. При необходимости экспортируй \
сертификат повторно, указав кодировку DER/BASE64.",
    "not_cert": "Мне кажется, что это не сертификат. Я не хочу проверять этот файл, дай мне что-то другое.",
    "checks": "\n• ".join(ok) + "\n\n" + "\n• ".join(not_ok),
    "settings": "Ты можешь задать себе индививидуальные настройки для проверки сертификатов:\n\
1. Не будет проверяться совпадаение ИНН из сертификата и подписи к файлу. Если ИНН указан в подписи к файлу, настройка \
будет проигнорирована.\nПолезно для массовой проверки сертификатов. Ответственность за проверку ИНН остается на тебе.\n\
2. Если не удалось составить тройной идентификатор по полученным данным, будет показан СНИЛС из сертификата.\
Полезно для поиска пользователя в КеАдмине.\n\
3. Не будет показываться отпечаток сертификата, чтобы сократить ответ на успешную проверку сертификата. Настройка \
будет проигнорирована, если распознать отпечаток из файла не удалось при проверке."
}

# Список УЦ, прошедших аккредитацию по 476-ФЗ. Словарь в формате {"ОГРН": Дата_получения_аккредитации}.
# Далее в комментарии указывается наименование УЦ для удобства
ACCREDITATION = {"1047707030513": datetime(2021, 7, 1),  # Федеральная налоговая служба
                 "1047797019830": datetime(2021, 7, 1),  # Федеральное казначейство
                 "1037700013020": datetime(2021, 7, 1),  # Центральный банк Российской Федерации
                 "1065074061579": datetime(2020, 10, 27),  # "Энергоцентр"
                 "1177746857045": datetime(2020, 11, 23),  # "Модум"
                 "1022301598549": datetime(2020, 12, 4),  # «Тандер»
                 "1105260001175": datetime(2020, 12, 4),  # "Аналитический центр"
                 "1144400000425": datetime(2020, 12, 18),  # "Совкомбанк"
                 "1027707013806": datetime(2020, 12, 30),  # «Электронная Москва»
                 "1027600787994": datetime(2020, 12, 30),  # «Тензор»
                 "1022302380319": datetime(2020, 12, 30),  # «Центр Бухгалтерских услуг»
                 "1027700485757": datetime(2020, 12, 30),  # «Федеральная кадастровая палата»
                 "1027700071530": datetime(2021, 5, 18),  # «Такском»
                 "1026605606620": datetime(2021, 6, 21),  # «СКБ Контур»
                 "1116673008539": datetime(2021, 6, 21),  # «Сертум-Про»
                 "1027739642281": datetime(2021, 6, 24),  # «Тинькофф Банк»
                 "1027700132195": datetime(2021, 7, 1),  # «Сбербанк России»
                 "1057812752502": datetime(2021, 7, 1),  # «КОРУС Консалтинг СНГ»
                 "1167746840843": datetime(2021, 7, 1),  # "АЙТИКОМ"
                 "1027739185066": datetime(2021, 7, 1),  # «ИнфоТеКС»
                 "1027739019142": datetime(2021, 7, 1),  # «Промсвязьбанк»
                 "1097746299353": datetime(2021, 7, 20),  # «Единая электронная торговая площадка»
                 "1024001434049": datetime(2021, 7, 20),  # «КАЛУГА АСТРАЛ»
                 "1047796526546": datetime(2021, 7, 20),  # «Научно-производственный центр «1С»
                 "1047833006099": datetime(2021, 7, 20),  # «ГАЗИНФОРМСЕРВИС»
                 "1097746819720": datetime(2021, 8, 16),  # «Гринатом»
                 "1197746000000": datetime(2021, 8, 16),  # «Почта России»
                 "5167746487651": datetime(2021, 8, 16),  # "ЭТП ГПБ Консалтинг"
                 "1027739609391": datetime(2021, 9, 8),  # ВТБ
                 "1027739113049": datetime(2021, 9, 8),  # Инфотекс
                 "1027700034493": datetime(2021, 9, 8),  # X5
                 "1077758841555": datetime(2021, 10, 1),  # РЖД
                 "1027700381290": datetime(2021, 10, 1),  # РНКБ (банк Крыма)
                 "1027700149124": datetime(2021, 10, 1),  # МТС
                 "1022300003703": datetime(2021, 11, 24),  # Банк Кубань Кредит
                 "1027809169585": datetime(2021, 12, 20),  # Мегафон
                 "1027707000441": datetime(2021, 12, 20),  # Сбер
                 "1152311003305": datetime(2021, 12, 13),  # Минсельхоз
                 "1027700166636": datetime(2021, 12, 13),  # Билайн
                 "1037739877295": datetime(2021, 12, 29),  # РЖД
                 "1027800000140": datetime(2022, 2, 10),  # Банк Санкт-Петербург
                 }

# History accreditation:
# "1037739514196": datetime(2020, 10, 27),  # Генеральная прокуратура. Expired - 01.01.2022