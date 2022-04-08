import re
import fsb795  # Часть библиотеки была модифицирована
import logging
import config
import traceback
from datetime import datetime, timedelta
from requests import Session, get, post
from bs4 import BeautifulSoup


logger = logging.getLogger()
logger.setLevel(logging.INFO)
FSS = set()  # Список УЦ с портала ФСС


class RedMessage(Exception):
    """Ошибка"""


class OrangeMessage(Exception):
    """Предупреждение"""


class Certificate(fsb795.Certificate):
    """Сертификат X509. path - Путь до файла *.cer"""

    class _Diadoc:
        """Все, что можно получить от Диадока"""

        def __init__(self):
            self.success_request = False
            self.parameters = {}

        def send_request(self, path: str):
            """Отправка сертификата на проверку в Диадок"""

            url = "https://diadoc.kontur.ru/certificate/CheckFile"
            # noinspection PyBroadException
            try:
                with open(path, "rb") as cert, post(url, files={"file": cert}, timeout=3) as req:
                    self.success_request = True
                # Интересны только первые 2 блока <pre> на странице с ответом
                pre_blocks = BeautifulSoup(req.text, "html.parser").findAll("pre", limit=2)
                for block in pre_blocks:
                    for key, value in re.findall("(.*?):(.*?)[,\n]", block.text):
                        self.parameters[key.strip()] = value.strip()
            except Exception as ex:
                logger.error(f"Request to diadoc.kontur.ru has been failed. {ex}.")

        def __getattr__(self, item):
            return self.parameters.get(item)

    # _diadoc_request - флаг отправки сертификата на проверку в Диадок.
    # False полезен для тестирования, чтобы лишний раз не отправлять сертификат в Диадок и не ждать его проверки
    def __init__(self, path: str, _diadoc_request=True):
        super().__init__(path)
        if self.pyver:
            self.path = path
            self.subject = self.subjectCert()[0]  # Блок Субъект
            self.issuer = self.issuerCert()[0]  # Блок Издатель
            self.validity = self.validityCert()  # Даты действия
            self.validity_before = self.validity.get("not_before")  # Дата начала действия
            self.validity_after = self.validity.get("not_after")  # Дата окончания действия
            self.subject_ogrn = self.subject.get("OGRN") or self.subject.get("OGRNIP")  # ОГРН из Субъекта
            self.issuer_ogrn = self.issuer.get("OGRN") or self.issuer.get("OGRNIP")  # ОГРН из Издателя
            self.subject_inn = self.subject.get("INNLE") or self.subject.get("INN")  # ИНН Субъекта
            self.snils = self.subject.get("SNILS")  # СНИЛС Субъекта
            self.unstructured_name = self.subject.get("unstructuredName")  # Неструктурированное имя Субъекта
            self.personal = not bool(self.subject_ogrn or self.subject.get("INNLE"))  # Флаг сертификата ФЛ
            self.key_usage = self.__find_key_usage()
            self.cert_policies = self.__find_cert_policies()
            self.diadoc = self._Diadoc()
            if _diadoc_request:
                self.diadoc.send_request(self.path)

    def __find_key_usage(self) -> str:
        """Поиск Идентификатора ключа центра сертификатов ФСС"""

        for ext in self.cert["extensions"]:
            # 2.5.29.35 - OID расширения Идентификатор ключа центра сертификатов
            if str(ext["extnID"]) == "2.5.29.35":
                return ext["extnValue"].prettyPrint()[14:54].upper()

    def __find_cert_policies(self) -> str:
        """Состав расширения Политики сертификата"""

        for extension in self.cert['extensions']:
            # 2.5.29.32 - OID расширения Политики сертификата
            if str(extension["extnID"]) == "2.5.29.32":
                return extension["extnValue"].prettyPrint()
        return ""


def check_all(cert: Certificate,
              inn: str, all_checks: bool = True, personal: bool = False, disabled_inn: bool = False) -> (set, set):
    """Все проверки.
    all_checks - флаг выполнения всех проверок.
    personal - флаг выполнения проверки сертификата физлица.
    disabled_inn - отключить проверку на ИНН.
    """

    errors = set()
    warns = {f"Проверялись только срок действия и отзыв сертификата, т.к. он получен в УЦ {cert.issuer['CN']}."}
    checks = {check_validity: (cert,),
              check_revoked: (cert,),
              check_inn: (cert, inn, disabled_inn)}
    if all_checks:
        warns = set()
        checks[check_snils] = (cert,)
        checks[check_inn] = (cert, inn, disabled_inn)
        checks[check_qualified] = (cert,)
        checks[check_egrul] = (cert,)
        checks[check_issuer] = (cert,)
        checks[check_fss] = (cert,)
        checks[check_accreditation] = (cert,)
        checks[check_cn] = (cert,)
        checks[check_extensions] = (cert,)
    if personal:
        checks.pop(check_inn)
        warns.add("Сертификат на ФЛ. Совпадение ИНН из сертификата и ИНН УЗ не проверялось. \
Работа возможна в тестовом режиме. Подробнее в знании `13348`.")
    # В зависимости от параметров будет сформирован определенный словарь с проверками
    for check, params in checks.items():
        # noinspection PyBroadException
        try:
            # Каждая проверка может вернуть только 1 из 3 результатов
            # None - успешная проверка, RedMessage - ошибка, OrangeMessage - предупреждение
            check(*params)
        except RedMessage as error:
            errors.add(error.args[0])
        except OrangeMessage as warning:
            warns.add(warning.args[0])
        except Exception:
            logger.critical(f"{check.__name__} check failed")
            logger.critical(traceback.format_exc())
            return
    logger.info(f"{len(checks)} checks passed. Extra options: all_checks={all_checks}, personal={personal}")
    return errors, warns


def update_fss():
    """Обновление списка доверенных УЦ с портала ФСС"""

    global FSS
    url_auth = "http://portal.fss.ru/fss/auth"
    url_data = "http://portal.fss.ru/fss/analytics/cross-certification"
    timeout = 5
    # noinspection PyBroadException
    try:
        with Session() as session:
            session.post(url_auth, data={"login": "demo", "password": "demo"}, timeout=timeout)  # Авторизация
            soup = BeautifulSoup(session.get(url_data, timeout=timeout).text, "html.parser")  # Скачивание данных
            table = soup.body.table.tbody.findAll(name="tr")  # Поиск таблицы
    except Exception as exc:
        logger.critical(exc.args[0])
        with open("./FSS_reserve.html", encoding="utf-8") as file:
            soup = BeautifulSoup(file, "html.parser")
            table = soup.body.findAll(name="table")[8].tbody.findAll(name="tr")
            logger.info(f"FSS CA list was downloaded from reserve file")
    finally:
        for record in table:
            row = record.findAll(name="td")
            # Запись в формате (Наименование УЦ, Идентификатор ключа)
            FSS.add((str(row[1]), str(row[3])))
        logger.info(f"{len(FSS)} FSS CA from portal.fss.ru")


def check_validity(cert: Certificate):
    """Проверка срока действия"""

    if not cert.validity_before <= datetime.today() - timedelta(hours=5) <= cert.validity_after:
        raise RedMessage("Срок действия сертификата истек.")
    days = (cert.validity_after - (datetime.today() - timedelta(hours=5))).days + 1
    if cert.diadoc.PrivateKeyIsExpired == "True":
        raise RedMessage("Срок действия закрытого ключа истек.")
    if days < 30:
        translator = "день" if days in (1, 21) else ("дня" if days in (2, 3, 4, 22, 23, 24) else "дней")
        raise OrangeMessage(f"Срок действия сертификата закончится через {days} {translator}.")


def check_revoked(cert: Certificate):
    """Проверка отозванности"""

    if cert.diadoc.RevocationCheckResult == "RevocationStatus: Revoked":
        raise RedMessage("Сертификат отозван.")


def check_issuer(cert: Certificate):
    """Проверка издателя"""

    if str(cert.issuer_ogrn) in config.NOT_VALID_CA:
        raise RedMessage(f"УЦ {cert.issuer['CN']} является недобросовестным.")


def check_inn(cert: Certificate, inn: str, disabled=False):
    """Проверка ИНН"""

    if cert.subjectCert()[0].get("INNLE"):
        if not cert.subjectCert()[0].get("INN"):
            # До 01.01.2022 был переходный период и такие сертификаты принимались. Источник - инцидент 33842466
            if cert.validity_before > datetime(2022, 1, 1):
                raise RedMessage("В сертификате ЮЛ обязаны присутствовать оба поля ИНН и ИННЮЛ.")
    if disabled:
        raise OrangeMessage(f"ИНН не проверялся. ИНН в сертификате - `{cert.subject_inn}`.")
    if cert.subject_inn is None:
        raise RedMessage("В сертификате не указан ИНН.")
    if not inn.strip("0"):
        raise RedMessage(f"Введен нулевой или не введен ИНН УЗ. \
Используй справку о боте, чтобы узнать, как его указать. ИНН в сертификате - `{cert.subject_inn}`.")
    if str(cert.subject_inn).rjust(12, "0") != inn.rjust(12, "0"):
        raise RedMessage(f"ИНН из сертификата `{cert.subject_inn}` не совпадает с ИНН УЗ `{inn}`.")


def check_cn(cert: Certificate):
    """Проверка поля CN"""

    cn = str(cert.subject.get("CN"))
    sn = str(cert.subject.get("SN"))
    gn = str(cert.subject.get("GN"))
    if cn.lower() == " ".join((sn, gn)).lower() and cert.subject.get("OGRN"):
        raise RedMessage("Поле CN в сертификате заполнено ФИО, а не названием организации.")


def check_snils(cert: Certificate):
    """Проверка СНИЛС"""

    if cert.snils is None:
        raise RedMessage("В сертификате не указан СНИЛС.")


def check_fss(cert: Certificate):
    """Проверка условий для ФСС"""

    if not FSS:
        raise OrangeMessage("Не удалось загрузить данные с портала ФСС. \
Портал недоступен или загрузка завершилась ошибкой.")
    if not cert.key_usage:
        raise OrangeMessage("\
Сертификат не подойдет для работы с ФСС, т.к. \
в сертификате не указан Идентификатор ключа центра сертификатов.")
    ca = cert.issuer.get("CN")
    # Иногда попадаются сертификаты с заполнением наименования УЦ в кодировке Windows-1251
    # Из-за невозможности декодировать первый байт проверка падает с ошибкой.
    # Для этого сделано перекодирование в utf-8 с игнорирированием проблемных байтов
    if not isinstance(ca, str):
        ca = str(bytes(ca), encoding="utf-8", errors="ignore")
    for line in FSS:
        if cert.key_usage in line[1] and ca in line[0]:
            break
    else:
        raise OrangeMessage(f"\
Сертификат не подойдет для работы с ФСС, т.к. \
пара 'Идентификатор ключа—Издатель' не найдена на портале ФСС.\n\
Издатель — `{ca}`;\n\
Идентификатор ключа — `{cert.key_usage}`;")
    if str(cert.subject.get("1.2.643.3.141.1.1")) == "0000000000":
        raise OrangeMessage("Сертификат не подойдет для работы с ФСС, т.к. в нем нулевой РН ФСС.")
    if not cert.personal and not cert.subject_ogrn:
        raise OrangeMessage("Для работы с ФСС необходимо выполнить действия из пункта 5 знания `9529`.")


def check_egrul(cert: Certificate):
    """Проверка отметок в ЕГРЮЛ"""

    # Здесь на боевом сервере указан focus_api_token
    if cert.personal:
        return
    ogrn = str(cert.subject_ogrn)
    inn = str(cert.subject_inn)
    if ogrn != "None":
        marks = get(r"https://focus-api.kontur.ru/api3/analytics", {"key": focus_api_token, "ogrn": ogrn})
    else:
        marks = get(r"https://focus-api.kontur.ru/api3/analytics", {"key": focus_api_token, "inn": inn})
    if marks.status_code != 200:
        if marks.status_code == 400:
            if marks.text == "inn/ogrn param is not specified":
                if str(cert.subject_inn).strip("0").startswith("99"):
                    raise OrangeMessage(f"Проверка отметок ЕГРЮЛ не выполнялась, т.к. организация иностранная.")
        logger.error(f"Ошибка запроса Фокус.API | Status code {marks.status_code} | {marks.text}")
        if ogrn != "None":
            raise OrangeMessage(f"Ошибка запроса Фокус.API. \
Проверь отметки ЕГРЮЛ https://focus.kontur.ru/entity?query={ogrn}")
        else:
            raise OrangeMessage(f"Ошибка запроса Фокус.API. Проверь отметки ЕГРЮЛ.")
    if not marks.json():
        if str(cert.subject_inn).strip("0").startswith("99"):
            raise OrangeMessage(f"Проверка отметок ЕГРЮЛ не выполнялась, т.к. организация иностранная.")
        if len(ogrn) == 13:
            raise RedMessage(f"В ЕГРЮЛ не найдено ЮЛ c ОГРН `{ogrn}`.")
        raise RedMessage(f"В ЕГРИП не найдено ИП c ОГРНИП `{ogrn}`.")
    analytics = marks.json()[0]["analytics"]
    valid_marks = any((analytics.get("m5006"), analytics.get("m5007")))
    if marks.json()[0].get("inn").rjust(12, "0") != inn.rjust(12, "0"):
        raise RedMessage(f"\
В ЕГРЮЛ по ОГРН `{ogrn}` ИНН `{marks.json()[0].get('inn')}`. \
В сертификате другой ИНН - `{inn}`.")
    req = get(r"https://focus-api.kontur.ru/api3/egrDetails", {"key": focus_api_token, "ogrn": ogrn})
    markers = ("Ликвидация ЮЛ",
               "Прекращение ЮЛ путем реорганизации в форме присоединения",
               "Прекращение деятельности ИП",
               "Запись о недостоверности сведений, включенных в ЕГРЮЛ")
    organization = req.json()[0].get("UL") or req.json()[0].get("IP")
    for record in organization["egrRecords"]:
        if record["name"] in markers[:3]:
            if len(ogrn) == 13:
                raise RedMessage(f"ЮЛ с ОГРН `{ogrn}` ликвидировано.")
            else:
                raise RedMessage(f"ИП с ОГРНИП `{ogrn}` ликвидирован.")
        if valid_marks:
            if record["name"] == markers[2]:
                rec_date = ".".join(record["date"].split("-")[::-1])
                if datetime.strptime(record["date"], "%Y-%m-%d") <= cert.validity_before:
                    raise RedMessage(f"\
В ЕГРЮЛ есть запись о недостоверности данных. Запись внесена {rec_date}, \
сертификат получен позже - {cert.validity_before:%d.%m.%Y}.")
                else:
                    raise OrangeMessage(f"\
В ЕГРЮЛ есть запись о недостоверности данных. Запись внесена {rec_date}, \
сертификат получен раньше - {cert.validity_before:%d.%m.%Y}.")


def check_qualified(cert: Certificate):
    """Проверка квалифицированности"""

    if not cert.diadoc.success_request:
        raise OrangeMessage(f"Не удалось проверить сертификат на квалифицированность, т.к. запрос на сервер \
https://diadoc.kontur.ru/certificate/check завершился ошибкой.")
    if cert.diadoc.IsSatisfiedByType == "False":
        if not cert.diadoc.QualifiednessErrorMessage:
            raise RedMessage("Сертификат неквалифицированный.")
        raise RedMessage(f"Сертификат неквалифицированный: {cert.diadoc.QualifiednessErrorMessage}")


def check_accreditation(cert: Certificate):
    """Проверка аккредитации УЦ"""

    ogrn = str(cert.issuer_ogrn)
    if cert.validity_before > datetime(2021, 7, 1):
        if ogrn not in config.ACCREDITATION:
            raise RedMessage(f"Сертификат получен после 01.07.2021, при этом УЦ {cert.issuer['CN']} \
не имеет аккредитации по новым правилам.")
        elif cert.validity_before < config.ACCREDITATION[ogrn]:
            raise RedMessage(f"Сертификат получен {cert.validity_before:%d.%m.%Y}, при этом аккредитация \
УЦ {cert.issuer['CN']} получена {config.ACCREDITATION[ogrn]:%d.%m.%Y}.")


def check_extensions(cert: Certificate):
    """Проверка корректности расширений сертификата"""

    key_usage = cert.KeyUsage()  # cert.KeyUsage() не то же самое, что cert.key_usage
    cert_policies = cert.cert_policies
    bad_extensions = []
    if not cert_policies:
        bad_extensions.append('    - Отсутствует расширение "Политики сертификата".')
    # 300806062a8503647101 - HEX значение класса KC1
    elif "300806062a8503647101" not in cert_policies:
        bad_extensions.append('    - В расширении "Политики сертификата" не указан класс средства ЭП КС1.')
    if not key_usage:
        bad_extensions.append('    - Отсутствует расширение "Использование ключа".')
    else:
        if "keyEncipherment" not in key_usage:
            bad_extensions.append('    - В расширении "Использование ключа" отсутствует значение "Шифрование ключей".')
        if "dataEncipherment" not in key_usage:
            bad_extensions.append('    - В расширении "Использование ключа" отсутствует значение "Шифрование данных".')
    bad_extensions = "\n".join(bad_extensions)
    if bad_extensions:
        raise RedMessage(f"В сертификате нет обязательных параметров в расширениях:\n{bad_extensions}")


update_fss()
