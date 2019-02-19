# !/usr/bin/env python
# -*- coding: utf-8 -*-

########################################################################################
### Fichier :      vault2keepass.py
### Description :  Script python permettant d'exporter le contenu de Vault vers KEEPASS
### Version :      v1.0
### Contributeur : v1.0 -> Mohamed Fakher MEDDEB
### Historique :   v1.0 -> Creation du script
########################################################################################

"""

Python Script that allows you to export
VAULT Hasicorp Repository content to a 
KEEPASS V2 DATA File.

This Script is based on pykeepass library to build
KEEPASS V2 DATA Files and hvac library to connect
to your VAULT Hashicorp Repository.

"""

from __future__ import print_function
from __future__ import unicode_literals

import hvac
import pykeepass
import config as CONF


def clean_str(string):
    """
    Remove last ans first '/' from directory.
    """
    return string.strip('/')


def clean_initial_repo(repo):
    """
    Clean the string and add first and last '/' 
    to get the intial repository
    """
    repo = clean_str(repo)
    if repo[0] != '/':
        repo = '/{}/'.format(repo)

    return repo


def print_progress_bar(iteration, total, prefix='', suffix='', length=100):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
    """
    decimals = 1
    fill = '█'
    percent = ("{0:." + str(decimals) + "f}").format(
        100 * (iteration / float(total))
    )
    filled_length = int(length * iteration // total)
    bar_state = fill * filled_length + '-' * (length - filled_length)
    print('\r%s |%s| %s%% %s' % (prefix, bar_state, percent, suffix), end='\r')

    if iteration == total: # Print New Line on Complete
        print()


def get_token_by_role_id(roleid, secretid, authurl):
    """
    Send http request to get the token.
    """
    response = CONF.REQUESTS.post( 
        authurl, 
        verify=False, 
        json={
            "role_id" : roleid,
            "secret_id" : secretid
        } 
    )

    return response.json().get('auth').get(
        'client_token'
    ) # Return Token informations


def get_all_data_informations(path, client):
    """
    Get all secrets and folders in a directory.
    """
    # Initialize folders_list, secrets_list vars
    folders_list = []
    secrets_list = []

    # Test if directory exists in vault
    if client.list(path):
        # Get all directory data
        vault_list = client.list(path).get(
            'data'
        ).get('keys')

        # Separate Folders and Secrets into different lists
        for key in vault_list:
            if '/' in key:
                folders_list.append(
                    '{0}{1}'.format(
                        path,
                        key
                    )
                )
    
            else:
                secrets_list.append(
                    '{0}{1}'.format(
                        path,
                        key
                    )
                )                

    return folders_list, secrets_list


def recursive_get_all_informations(path, client):
    """
    Get all secrets and foders in 
    VAULT Hashicorp Repository.
    """
    # Initialize all_secrets_paths, all_folders_paths vars
    all_secrets_paths = []
    all_folders_paths = []

    # Get the first folders and secrets in vault's root directory
    folders_list, secrets_list = get_all_data_informations(
        path, 
        client
    )
    
    # Keep searching until no informations in folders_list and secrets_list
    while ( folders_list or secrets_list ):
        # Stock all secrets in a list an remove them from secrets_list
        for secret in secrets_list:
            secrets_list.remove(
                secret
            )

            if secret not in all_secrets_paths:
                all_secrets_paths.append(
                    secret
                )
        
        # Stock all folders in a list an remove them from folders_list
        for folder in folders_list:
            folders_list.remove(
                folder
            )

            # Search for other secrets and folders
            tmp_folders_list, tmp_secrets_list = get_all_data_informations(
                folder, 
                client
            )

            # Append secrets and folders in lists
            folders_list.extend(
                tmp_folders_list
            )

            secrets_list.extend(
                tmp_secrets_list
            )

            if folder not in all_folders_paths:
                all_folders_paths.append(
                    folder
                )

    return all_folders_paths, all_secrets_paths


def get_keepass_file(keepass_db, password, keyfile):
    """
    Create and return the new KEEPASS File.
    """
    # Create keepass file from the keepass base file (keepass empty file)
    keepass = pykeepass.PyKeePass(
        CONF.KEEPASS_BASEFILE, 
        password=CONF.KEEPASS_DEFAULT_PASSWORD
    )

    # Change the password of the file
    keepass.password = password
    
    # Change the keyfile of the file
    keepass.keyfile = keyfile

    # Save the keepass file into a new keepass file that will be used 
    keepass.save(
        filename=keepass_db
    )
    
    # Return the new keepass file
    return pykeepass.PyKeePass(
        keepass_db, 
        password=password, 
        keyfile=keyfile
    )


def find_secrets_in_directory(directory, client):
    """
    Find all secrets in a directory.
    """
    # Initialize secrets_names var
    secrets_names = []

    # Test if directory exists in vault
    if client.list(directory):
        # Get all directory data
        directory_list = client.list(directory).get(
            'data'
        ).get('keys')
        
        # Get all data that doesn't contain '/' (Get only secrets from the list)
        for key in directory_list:
            if '/' not in key:
                secrets_names.append(
                    '{}/{}'.format(
                        directory, 
                        key
                    )
                )

    return secrets_names


def clean_secret_details(vault_secret):
    """
    Clean all secret data.
    """
    username = '' if vault_secret.get('UserName')==None \
    else vault_secret.get('UserName')

    password = '' if vault_secret.get('Password')==None \
    else vault_secret.get('Password')

    url = vault_secret.get('URL')
    notes = vault_secret.get('Notes')

    return username, password, url, notes


def add_all_secrets_to_group(keepass, secrets_names, group, client):
    """
    Add all group secrets.
    """
    for secret in secrets_names: # Read all group's secrets 
        if client.read(secret):
            last_slash_index = int(
                [m.start() for m in CONF.RE.finditer('/', secret)][-1:][0]
            ) # Find last slash index in directory 

            # Extract the secret name from directory
            secret_name = secret[last_slash_index+1:]
            
            vault_secret = client.read(
                secret
            ).get('data') # Get secret data from vault

            username, password, url, notes = clean_secret_details(
                vault_secret
            ) # Clean Secret data
           
            keepass.add_entry( 
                group, 
                secret_name, 
                username, 
                password, 
                url=url, 
                notes=notes, 
                force_creation=True 
            ) # Add secret to keepass file and force creation if already exists

            # Add secret to secret added List
            CONF.SECRETS_ADDED.append(
                secret
            )


def group_verify_add_secrets(group, directory_path, keepass, client):
    """
    Test if group secrets already created 
    (group.path is unique for every group).
    """
    if group.path not in CONF.GROUPS_SECRETS_ADDED:
        secrets_names = find_secrets_in_directory(
            directory_path, 
            client
        ) # Get all group secrets

        add_all_secrets_to_group(
            keepass, 
            secrets_names, 
            group, 
            client
        ) # Add all group secrets to keepass file

        CONF.GROUPS_SECRETS_ADDED.append(
            group.path
        ) # Add group.path to groups secret added list


def recursive_directories_creation(directory_paths, directory_path, 
                                   group, keepass, client):
    """
    Create recursively all KEEPASS File folders.
    """

    for next_directory in directory_paths:

        directory_path = '{}{}'.format( 
            clean_initial_repo(directory_path), 
            clean_str(next_directory) 
        ) # Build Complete Directory Path From Vault Repository

        # Get group's sub-groups
        subgroups = group.subgroups
        
        # Search if the group is already created 
        found = False
        for subgroup in subgroups:
            if subgroup.name == next_directory:
                found = True
                group = subgroup
 
                group_verify_add_secrets(
                    group, 
                    directory_path, 
                    keepass, 
                    client
                ) # Verify group and add secrets
        
        # Create group if it doesn't exist
        if not found:
            group = keepass.add_group(
                group, 
                next_directory, 
                icon='49'
            )
            
            # Increment GROUPS_ADDED var
            CONF.GROUPS_ADDED += 1
            
            group_verify_add_secrets(
                group, 
                directory_path, 
                keepass, 
                client
            ) # Verify group and add secrets

    return group


def create_keepass_file(client, vault_repo, directories):
    """
    Create the new KEEPASS File.
    """
    keepass = get_keepass_file(
        CONF.KEEPASS_FILE, 
        CONF.PASSWORD, 
        CONF.KEYFILE
    ) # Build a new Keepass File from the Keepass Base File

    CONF.LOGGER.debug(
        '{}ADDING DIRECTORIES AND SECRETS \
        TO KEEPASS ...: {}{}'.format(
            CONF.YELLOW_TERMINAL_COLOR, 
            CONF.TERMINAL_COLOR, 
            keepass.filename.split('/')[-1:][0]
        )
    )
    
    for directory in directories:
        directory_paths = directory.replace(
            vault_repo, ""
        ).split('/')[:-1] # Split All Directory Paths

        # Get the first Directory
        first_directory = directory_paths[0]

        directory_paths.remove(
            first_directory
        )

        directory_path = '{}{}'.format( 
            vault_repo, 
            clean_str(first_directory) 
        ) # Build Complete Directory Path From Vault Repository

        group = keepass.find_groups(
            name=first_directory, 
            first=True
        ) # Search if a Group with the name of first directory already exists

        if group is not None: 
            group_verify_add_secrets(
                group, 
                directory_path, 
                keepass, 
                client
            ) # Verify and add if the Group does'nt contain his Secrets

            group = recursive_directories_creation(
                directory_paths, 
                directory_path, 
                group, 
                keepass, 
                client
            ) # Create sub-groups

        else:
            group = keepass.add_group(
                keepass.root_group, 
                first_directory, 
                icon='49'
            ) # Create group if it doesn't exist

            # Increment GROUPS_ADDED var
            CONF.GROUPS_ADDED += 1

            group_verify_add_secrets(
                group, 
                directory_path, 
                keepass, 
                client
            ) # Verify and add if the Group does'nt contain his Secrets 

            group = recursive_directories_creation(
                directory_paths, 
                directory_path, 
                group, 
                keepass, 
                client
            ) # Create sub-groups

        print_progress_bar(
            CONF.GROUPS_ADDED, 
            len(directories), 
            prefix='Progress:', 
            suffix='Complete', 
            length=75
        ) # Print progress bar

    CONF.LOGGER.debug(
        '{}ALL DIRECTORIES AND SECRETS ADDED \
        SUCCESSFULLY TO KEEPASS: {}{}'.format(
            CONF.GREEN_TERMINAL_COLOR, 
            CONF.TERMINAL_COLOR, 
            keepass.filename.split('/')[-1:][0]
        )
    )
    
    # Save the keepass file directory: keepassfiles/vault2keepass/
    keepass.save()
    return keepass


def export_to_keepass(vault_url, vault_repo, ssl_verify=True):
    """
    Export data from VAULT Hashicopr Repository
    to a new KEEPASS File.
    """
    client = hvac.Client(
        url=vault_url, 
        token=CONF.TOKEN, 
        verify=ssl_verify
    ) # Connect to Vault Database
    
    vault_repo = clean_initial_repo(
        vault_repo
    ) # Clean Repository URL  
    
    # Initialize Directories and Secrets vars
    directories = []
    secrets = []
    
    # Test if provided Vault Repository Exists
    if client.list(vault_repo):    
        CONF.LOGGER.debug(
            '{}ROOT FOLDER FOUND: {}{}'.format(
                CONF.GREEN_TERMINAL_COLOR, 
                CONF.TERMINAL_COLOR, 
                vault_repo
            )
        )
        LOGGER.debug(
            '{}GETTING ALL SECRETS AND DIRECTORIES \
            INFORMATIONS.... : {}{}'.format(
                CONF.BLUE_TERMINAL_COLOR, 
                CONF.TERMINAL_COLOR, 
                vault_repo
            )
        )
        
        directories, secrets = recursive_get_all_informations(
            vault_repo, 
            client
        ) # Get All Directories And Secrets From Vault Database

        CONF.LOGGER.debug(
            '{}TOTAL FOUND: {}SECRETS: {} || \
            DIRECTORIES: {}'.format(
                CONF.GREEN_TERMINAL_COLOR, 
                CONF.TERMINAL_COLOR, 
                len(secrets), 
                len(directories)
            )
        )   
    else: 
        CONF.SYS.excepthook = CONF.excepthook # Raise Errors without Treceback
        raise Exception(
            '{}ROOT FOLDER DOES NOT EXIST: {}{}'.format(
                CONF.RED_TERMINAL_COLOR, 
                CONF.TERMINAL_COLOR, 
                vault_repo
            )
        )
    
    CONF.LOGGER.debug(
        '{}CREATING KEEPASS FILE KDBX \
        INFORMATIONS.... : {}{}'.format(
            CONF.BLUE_TERMINAL_COLOR, 
            CONF.TERMINAL_COLOR, 
            CONF.KEEPASS_FILE
        )
    )

    print_progress_bar(
        CONF.GROUPS_ADDED, 
        len(directories), 
        prefix='Progress:', 
        suffix='Complete', 
        length=75
    ) # Initial call to print 0% progress

    keepass = create_keepass_file(
        client, 
        vault_repo, 
        directories
    ) # Create Keepass File from Vault Data

    CONF.LOGGER.debug(
        '{}CREATION COMPLETE SUCCESSFULLY: {}{} || \
        CREATED: DIRECTORIES: {} SECRETS: {}'.format(
            CONF.GREEN_TERMINAL_COLOR, 
            CONF.TERMINAL_COLOR, 
            keepass.filename.split('/')[-1:][0], 
            CONF.GROUPS_ADDED, 
            len(CONF.SECRETS_ADDED)
        )
    )
    
    # Test if there's secrets not created
    if len(CONF.SECRETS_ADDED) != len(secrets):
        CONF.LOGGER.debug(
            '{}WARNING: {}SECRET(S) NOT CREATED: {}'.format(
                CONF.YELLOW_TERMINAL_COLOR, 
                CONF.TERMINAL_COLOR, 
                list(set(secrets) - set(CONF.SECRETS_ADDED))
            )
        )

if __name__ == '__main__':
    # Add argument parser. And All Arguments to be parsed.
    __parser__ = CONF.ARG_PARSER.ArgumentParser()
    
    __parser__.add_argument(
        '-p', '--password',
        required=False,
        help='Password to unlock the KeePass database'
    )
    __parser__.add_argument(
        '-f', '--keyfile',
        required=False,
        help='Keyfile to unlock the KeePass database \
        Deposit Directory: keepassfiles/keys'
    )
    __parser__.add_argument(
        '-t', '--token',
        required=False,
        default=CONF.OS.getenv(
            'VAULT_TOKEN',
            None
        ),
        help='Vault token'
    )
    __parser__.add_argument(
        '-v', '--vault',
        default=CONF.OS.getenv(
            'VAULT_ADDR',
            'https://localhost:8200'
        ),
        required=True,
        help='Vault URL'
    )
    __parser__.add_argument(
        '-k', '--ssl-no-verify',
        action='store_true',
        default=True if CONF.OS.getenv('VAULT_SKIP_VERIFY', False) else False,
        required=False,
        help='Whether to skip TLS cert verification'
    )
    __parser__.add_argument(
        '-aurl', '--authurl',
        required=False,
        help='Authentication URL to connect to vault'
    )
    __parser__.add_argument(
        '-rurl', '--repourl',
        required=True,
        help='Repository URL to stock secrets to vault'
    )
    __parser__.add_argument(
        '-rid', '--roleid',
        required=False,
        help='Role Id to connect to vault'
    )
    __parser__.add_argument(
        '-sid', '--secretid',
        required=False,
        help='Secret Id to connect to vault'
    )

    # Get the Arguments from the command line
    __args__ = __parser__.parse_args()
    
    
    CONF.PASSWORD = __args__.password if __args__.password \
    else CONF.KEEPASS_DEFAULT_PASSWORD # Get Password

    # Get keyfile name to build file directory
    CONF.KEYFILE = CONF.OS.path.join(
        CONF.KEEPASS_DIRECTORY_FILES, 
        'keys', 
        __args__.keyfile
    ) if __args__.keyfile else None

    # Build BASE KEEPASS File directory    
    CONF.KEEPASS_BASEFILE = CONF.OS.path.join(
        CONF.KEEPASS_DIRECTORY_FILES, 
        'base_keepass.kdbx'
    )

    # Build NEW KEEPASS File directory
    CONF.KEEPASS_FILE = CONF.OS.path.join(
        CONF.KEEPASS_DIRECTORY_FILES, 
        'vault2keepass', 
        'Vault2Keepass_{}.kdbx'.format(
            CONF.DATE_TIME.now().strftime(
                '%Y-%m-%d--%H-%M-%S'
            )
        )
    )

    if __args__.token:
        # If provided argument is a file read from it
        if os.path.isfile(__args__.token): 
            with open(__args__.token, 'r') as f:
                CONF.TOKEN = f.read().splitlines()[0]
        else:
            CONF.TOKEN = __args__.token
    else:
        if __args__.roleid and __args__.secretid:
            # If Token not provided get token by 
            # role id and secret id and authentication URL.
            CONF.TOKEN = get_token_by_role_id(
                __args__.roleid, 
                __args__.secretid,
                '{0}{1}'.format(
                    __args__.vault,
                    __args__.authurl
                )
            )
        else:
            CONF.SYS.excepthook = CONF.excepthook # Raise Errors without Treceback 
            raise Exception(
                '{}Please either provide your Token or your \
                RoleId and SecretId and Authentication URL.{}'.format(
                    CONF.RED_TERMINAL_COLOR, 
                    CONF.TERMINAL_COLOR
                )
            )
    
    # If everything is provided and OK
    # we can export VAULT Hashicorp Repository to a 
    # NEW KEEPASS V2 DATA File.
    export_to_keepass(
        vault_url=__args__.vault,
        vault_repo=__args__.repourl,
        ssl_verify=not __args__.ssl_no_verify
    )