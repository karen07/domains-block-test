# Domains block test

Domains block test is a low-level TLS/SNI probe that tests domain names against a list of target IPv4 addresses using synthetic TLS ClientHello packets.

The program crafts TCP and TLS packets directly on a selected network interface, sends a ClientHello with the tested domain in SNI, and observes replies through libpcap. A matching TLS Alert increments the successful-response count; domains that receive too few such replies across the test attempts are written to `blocked.txt`.

This is a specialized filtering diagnostic, not a general HTTPS reachability test. It does not perform a normal browser-style TLS session or validate HTTP responses, and it requires sufficient privileges for direct packet capture and injection.

## Описание

Domains block test - низкоуровневая утилита TLS/SNI, которая проверяет доменные имена через список целевых IPv4 адресов с помощью синтетических пакетов TLS ClientHello.

Программа самостоятельно формирует TCP и TLS пакеты на выбранном сетевом интерфейсе, отправляет ClientHello с проверяемым доменом в SNI и наблюдает ответы через libpcap. Подходящая запись TLS Alert увеличивает счетчик успешных ответов, а домены, для которых за серию попыток получено слишком мало таких ответов, записываются в `blocked.txt`.

Это специализированная утилита для диагностики фильтрации, а не общий тест доступности HTTPS. Она не выполняет обычную TLS сессию как браузер и не проверяет HTTP ответы, а для прямого перехвата и отправки пакетов ей нужны достаточные права.

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
