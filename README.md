Цель проекта -- автоматизированное создание и последующее уничтожение виртуальной машины
в Amazon Elastic Cloud 2 (EC2) для выполнения функций прокси-сервера и, возможно, VPN.
В простейшем случае на машину ничего не ставится, а SOCKS прокси создаётся вызовом 
SSH:

       ssh -D localhost:<port> ec2-user@<ip_address>.

Язык Python, используются библиотеки boto3, json, botocore.

Что вам понадобится:

 - Учётная запись на Amazon-е, привязанная банковская карта для оплаты (счёт выставляют в конце месяца).
 - Пользователь IAM с правами полного доступа в Amazon Elastic Cloud (EC2), из-под которого вы будет создавать виртуальные машины.
 - Настроенная Амазоновская аутентификация по ключу. У меня в Linux это выглядит так:

```
$ cd ~/.aws

$ ls -l 
total 15
-rw-r--r-- 1 user group 213 Jun 05 config
-rw------- 1 user group 480 Jul 13 credentials
```

В файле config описания профилей, в файле credentials закрытые части ключей, он должен быть закрыт на чтение кому попало.

```
$ cat config

[profile testAWS]
region = eu-central-1
output = json

[default]
region = eu-west-1
output = json
```

Регион ищем в Амазоне.  Для создания прокси лучше иметь отдельный профиль в AWS, названный как-нибудь нейтрально.

В файле credentials, конечно, ключи. Они получаются через консоль AWS, раздел IAM. Пример файла (ключи, конечно, "левые"):

```
[default]
aws_access_key_id = SIHUEWD6OKDOAGYUWOK6
aws_secret_access_key = CidubMidVoorOfbodsAgiacsyidBoojdysk!6Kna

[testAWS]
aws_access_key_id = NOKAJSHONTAFUDKACAF1
aws_secret_access_key = miBliteicDyWotjoajerph6Od+ofJugVickAitUf
```

## Использование двух машин для проброса SOCKS прокси

Создаётся ДВЕ машины в разных регионах с образованием цепочки прокси между ними (на второй /выходной/ машине
поднимается SOCKS сервер, а на первой /входной/ организуется проброс его порта клиенту. 
Или цепочка делается самим SSH (-J). 

Для чего? Для противодействия отслеживанию типа "на веб-сервер заходили отсюда, а кто был подключен к этому хосту в этот момент?".

Используется технология цепочечного SSH (multi-hop SSH).
Одна из машин назначается Back-End (с неё будет соединение с целевыми серверами), вторая Front-End (с ней будет соединяться ваша машина). Проброс соединения делается так:

```
ssh -i key.pem -o 'ProxyCommand = ssh -i key.pem ubuntu@<FRONTEND_IP> -W <BACKEND_IP>:22' -D 8050 ubuntu@<BACKEND_IP>
```

TODO:
 - поиск подходящего AMI ID
