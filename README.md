# Domains Block Test

A low-level TLS/SNI probe that tests domains against selected IPv4 addresses. It crafts
TLS ClientHello traffic, sends it directly through a network interface, and observes
replies using libpcap.

Низкоуровневая утилита для проверки доступности доменов через TLS/SNI на выбранных
IPv4-адресах. Она формирует TLS ClientHello, отправляет пакеты непосредственно через сетевой
интерфейс и отслеживает ответы с помощью libpcap.

## Описание

Программа самостоятельно формирует TCP и TLS пакеты на выбранном сетевом интерфейсе, отправляет ClientHello с проверяемым доменом в SNI и наблюдает ответы через libpcap. Подходящая запись TLS Alert увеличивает счётчик успешных ответов, а домены, для которых за серию попыток получено слишком мало таких ответов, записываются в `blocked.txt`.

Это специализированная утилита для диагностики фильтрации, а не общий тест доступности HTTPS. Она не выполняет обычную TLS сессию как браузер и не проверяет HTTP ответы, а для прямого перехвата и отправки пакетов ей нужны достаточные права.

## Разработка и проверка изменений

**Основные точки изменения:**

- `src/domains_block_test.c` - создание пакетов TLS ClientHello, отправка и захват ответов;
- `include/domains_block_test.h` - общие объявления и настройки;
- `CMakeLists.txt` - подключение сетевых библиотек.

**Поток данных:** `send_raw()` отправляет TCP SYN на выбранные IPv4-адреса
и порт 443. `read_raw()` связывает SYN/ACK с записью соединения по IP и порту,
затем формирует ACK и TLS ClientHello с очередным SNI из списка доменов.
Та же таблица используется для сопоставления ответов с доменами и удаления
завершённых/устаревших соединений.

**Критерий результата:** код считает подходящие TLS Alert: проверяет
`IP total length == 47`, первый байт TLS `0x15` и следующий байт `0x03`.
Это не подтверждение успешного TLS-handshake. После `TRY_COUNT` циклов
(`30` в текущем заголовке) в `blocked.txt` попадают домены с числом
учтённых Alert меньше `TRY_COUNT / 6`; строки содержат счётчик и домен.
Не следует интерпретировать этот эвристический результат как точный
диагноз сетевой блокировки.

**Проверка изменений:** Пакеты формируются на Ethernet/IP/TCP уровне:
изменение полей требует согласовать длины, TCP checksum, условия фильтрации
в `read_raw()` и ключи соединений. Отдельно проверяйте цикл SYN -> SYN/ACK
-> ClientHello -> Alert и логику подсчёта. В репозитории нет автоматических
тестов сетевого пути; результат зависит от интерфейса и окружения.

## Сборка

Нужны libpcap, CMake и git submodule `hashmap`.

```sh
git submodule update --init --recursive
cmake --preset release
cmake --build --preset release
```

Исполняемый файл:

```text
build/release/domains-block-test
```

## Использование

```text
Commands:
  Required parameters:
    -d  "/test.txt"  Domains file path
    -i  "/test.txt"  IPs file path
    -n  "test"       Network device name
    -r  "xxx"        Requests per second
```

Пример:

```sh
sudo ./build/release/domains-block-test \
    -d domains.txt \
    -i ips.txt \
    -n eth0 \
    -r 100
```

## Что проверяется

Для комбинаций доменов и IP программа формирует TCP/TLS probes на порт 443. SNI берется из списка доменов, а destination address - из списка IP.

Проект предназначен для массовой проверки поведения сети и серверов при TLS/SNI соединениях. Результат классификации сохраняется в `blocked.txt`, а во время работы выводится статистика отправленных и полученных пакетов.

## Лицензия

Проект распространяется под лицензией GNU Affero General Public License v3.0. Подробности см. в файле [LICENSE](LICENSE).
