# Synopsis

* Création de deux scripts PYTHON pour pemettre l'import/export d'un fichier KeePass vers l'outil Vault et vice-versa.


# Installation

## Installer Python 2.7 
* Sous windows pensez à ajouter, à la variable d’environnement PATH, le chemin vers le répertoire où python est installé "C:\Python27" et le chemin vers le dossier Srcipts "C:\Python27\Scripts".

## Créer un environnement virtuel:
* mac/linux/windows: $>virtaulenv venv

## Activer l'environnement virtuel :
* mac/linux: $source venv/bin/activate
* windows: >venv\Sciprts\activate

## Installer les modules python nécessaires:
* $>pip install -r requirements.txt


# Lancement des scripts

## De Vault Vers KeePass  : 

~~~
$ python vault2keepass.py -k -v <Vault-URL> -rurl <Répertoire vault de stockage> -aurl <URL vault d'authentification> -rid <Role id> -sid <Secret id> -f <nom du fichier keyfile>.key -p <mot de passe du fichier KeePass>
~~~

Où bien:
~~~
$ python vault2keepass.py -k -v <Vault-URL> -rurl <Répertoire vault de stockage> -t <Token> -f <nom du fichier keyfile>.key -p <mot de passe du fichier KeePass>
~~~

* Pensez à bien stocker les fichiers keepass sous le répertoire: keepassfiles/keepass2vault
* Pensez à bien stocker les fichiers keepass keyfile sous le répertoire: keepassfiles/keys
* Variable Obligatoires:
1. -v "Vault-URL" 
2. -t "Token" où bien -rid "Role id" -sid "Secret id"
3. -rurl "Répertoire de stockage dans Vault"
4. -aurl "URL Vault d'authentification" si on ne fournit pas le Token

* NB: Si on ne fournit pas le mot passe, le mot de passe par défaut pour le fichier KeePass qui va être crée est "123456789".

## De KeePass Vers Vault  : 

~~~
$ python keepass2vault.py <nom du fichier keepass>.kdbx -k -v <Vault-URL> -rurl <Répertoire vault de stockage> -aurl <URL vault d'authentification> -rid <Role id> -sid <Secret id> -f <nom du fichier keyfile>.key -p <mot de passe du fichier KeePass>
~~~

Où bien:
~~~
$ python keepass2vault.py <nom du fichier keepass>.kdbx -k -v <Vault-URL> -rurl <Répertoire vault de stockage> -aurl <URL vault d'authentification> -t <Token> -f <nom du fichier keyfile>.key -p <mot de passe du fichier KeePass>
~~~

* Vous trouverez les nouveaux fichiers keepass stockées sous le répertoire: keepassfiles/keepass2vault
* Pensez à bien stocker les fichiers keepass keyfile sous le répertoire: keepassfiles/keys
* Variable Obligatoires:
1. "nom du fichier keepass".kdbx
2. -v "Vault-URL" 
3. -t "Token" où bien -rid "Role id" -sid "Secret id"
4. -rurl "Répertoire de stockage dans Vault"
5. -aurl "URL Vault d'authentification" si on ne fournit pas le Token
6. -p "mot de passe du fichier KeePass"

* NB: La variable "-d" permet la suppression de la Répertoire de stockage dans Vault si elle existe déjà.
