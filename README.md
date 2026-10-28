# Domains Block Test

A low-level TLS/SNI probe that tests domains against selected IPv4 addresses. It crafts
TLS ClientHello traffic, sends it directly through a network interface, and observes
replies using libpcap.

Низкоуровневая утилита для проверки доступности доменов через TLS/SNI на выбранных
IPv4-адресах. Она формирует TLS ClientHello, отправляет пакеты непосредственно через сетевой
интерфейс и отслеживает ответы с помощью libpcap.

## Описание

Программа самостоятельно формирует TCP и TLS пакеты на выбранном сетевом интерфейсе, отправляет ClientHello с проверяемым доменом в SNI и наблюдает ответы через libpcap. Подходящая запись TLS Alert увеличивает счетчик успешных ответов, а домены, для которых за серию попыток получено слишком мало таких ответов, записываются в `blocked.txt`.

Это специализированная утилита для диагностики фильтрации, а не общий тест доступности HTTPS. Она не выполняет обычную TLS сессию как браузер и не проверяет HTTP ответы, а для прямого перехвата и отправки пакетов ей нужны достаточные права.

## Разработка и проверка изменений

**Основные точки изменения:**

- `src/domains_block_test.c` - создание пакетов TLS ClientHello, отправка и захват ответов;
- `include/domains_block_test.h` - общие объявления и настройки;
- `CMakeLists.txt` - подключение сетевых библиотек.

**Проверка изменений:** Изменения сетевых пакетов требуют пересчёта контрольных сумм и проверки формата пакета на реальном или изолированном интерфейсе. Для сборки используйте раздел "Сборка", для сценариев - "Использование"; сетевые результаты зависят от окружения.

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
