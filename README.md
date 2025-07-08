# Анализ сервисов

## Стенд

### Подготовка стенда

Для начала поднимаем стенд для дампа трафка

```bash
docker run -d --name firefox -e USER_ID=$(id -u) -e GROUP_ID=$(id -g) -p 5800:5800 -p 5900:5900 -v ./dump/:/dump -e SSLKEYLOGFILE=/dump/ssl.log jlesage/firefox
```

Далее устанавливаем утилиты для дампа

- Заходим в docker

```bash
docker exec -it firefox sh
```

- Устанавливаем tcpdump

```bash
apk add tcpdump
```
### Запись
Начинаем запись

```bash
tcpdump -i eth0 -w /dump/raw.pcap
```

Заканчиваем запить `^C`

## Обработка данных

- Открываем `raw.pcap` в Wireshark
- Устанавливаем ключ для TLS в Wireshark на `ssl.log`
