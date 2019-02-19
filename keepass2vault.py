# !/usr/bin/env python
# -*- coding: utf-8 -*-

########################################################################################
### Fichier :      vault2keepass.py
### Description :  Script python permettant d'exporter le contenu de KEEPASS vers Vault
### Version :      v1.0
### Contributeur : v1.0 -> Mohamed Fakher MEDDEB
### Historique :   v1.0 -> Creation du script
########################################################################################

"""

Python Script that allows you to export
KEEPASS V2 database to a VAULT Hasicorp Repository.

This Script is based on libkeepass library to read
KEEPASS V2 files and hvac library to connect
to your VAULT Hashicorp Repository.

"""

from __future__ import print_function
from __future__ import unicode_literals

import hvac
import libkeepass
import lxml.etree
import config as CONF


def safevalue(entry, path):
    """
    Return clean value text.
    """
    value = entry.find(path)
    if value is None:
        return None
    elif value.text is None:
        return None
    elif value.text == '':
        return None
    else:
        return value.text


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


def get_entry_name(entry):
    """
    Return cleaned entry name. 
    """
    value_entries = [
        'String[Key="Title"]/Value', 
        'String[Key="URL"]/Value', 'UUID'
    ]

    for path_choice in value_entries:
        value = safevalue(
            entry, 
            path_choice
        ) # Get clean entry value name or url 

        if value: # If entry has no name  
            if path_choice == 'UUID':
                return '< Unknown Entry Name >'
            else:
                return value


def get_entry_details(entry):
    """
    Return entry details.
    """
    return {
        e.find('Key').text: e.find('Value').text 
        for e in entry.findall('String')
    }


def get_group_name(group):
    """
    Return the group name.
    """
    return group.find('Name').text


def clean_str(string):
    """
    Remove last ans first '/' and spaces from directory.
    """
    return string.strip().strip('/').strip()


def clean_initial_repo(repo):
    """
    Clean the string and add first and last '/' 
    to get the intial repository
    """
    repo = clean_str(repo)
    if repo[0] != '/':
        repo = '/{}/'.format(repo)

    return repo


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


def export_entries_from_group(xmldata, group, parent_name=None):
    """
    Get total entries an xml elements.
    """
    group_name = get_group_name(
        group
    ) # Get the groop name
    
    path = '{}{}'.format(
        parent_name if parent_name else '',
        group_name if group_name else ''
    )  # Get the group path by parent name

    entries = group.findall(
        'Entry'
    ) # Get all group entries

    groups = group.findall(
        'Group'
    ) # Get all group sub-groups

    total_entries = [] # Declare total_entries var
    for e in entries:
        ed = get_entry_details(e) # Get entry details

        ed = dict(
            (k, v) for k, v in ed.iteritems()
        )
        
        ed['_entry_name'] = clean_str(
            get_entry_name(e)
        ) # Clean entry name

        ed['_path'] = clean_str(
            '{}'.format(path)
        ) # Clean path

        total_entries.append(ed) # Append entry to total entries

    for g in groups:
        sub_entries = export_entries_from_group( 
            xmldata, 
            g, 
            '{}/'.format(
                path if path else ''
            ) 
        ) # Get all group sub-groups recursively

        total_entries += sub_entries # Append sub-groups to total entries

    return total_entries


def export_entries(filename, password, keyfile=None):
    """
    Get total entries exported from keepass file.
    """
    with libkeepass.open(filename, password=password, keyfile=keyfile) as kdb:
        xmldata = lxml.etree.fromstring(
            kdb.pretty_print()
        ) # Get keepass data in xml format

        tree = lxml.etree.ElementTree(
            xmldata
        ) # Get the xml object of keepass data
        
        root_group = tree.xpath(
            '/KeePassFile/Root/Group'
        )[0] # Get the keepass file's root group

        all_entries = export_entries_from_group(
            xmldata, 
            root_group 
        )# Get all entries from keepass

        return all_entries


def find_similar_entries(vault_url, entry_name, ssl_verify=True):
    """
    Find similar entries if existed.
    """
    client = hvac.Client(
        url=vault_url, 
        token=CONF.TOKEN, 
        verify=ssl_verify
    ) # Connect to Vault Database

    entry = client.read(entry_name) # Read entry by name

    # Get the entry list if entry is not none
    entries = [entry] if entry else []
    index = 2
    while True:
        entry = client.read(
            '{} ({})'.format(
                entry_name, 
                index
            )
        ) # Get all entries with same name
        if entry:
            entries.append(entry)
        else:
            return entries

        index += 1


def get_next_similar_entry_index(vault_url, entry_name, ssl_verify=True):
    """
    Return number of entries with the same name.
    """
    return len(
        find_similar_entries(
            vault_url,
            entry_name,
            ssl_verify
        )
    ) + 1


def get_delete_informations(path, client):
    """
    Get Secrets ans Folders to delete.
    """
    folders_list = [] # Initialize folders_list
    secrets_list = [] # Initialize secrets_list

    if client.list(path): # Test if directory exists in vault
        vault_list = client.list(
            path
        ).get('data').get('keys') # Get all directory data

        # Separate Folders and Secrets into different lists.
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


def recursive_delete(path, client):
    """
    Delete Recursively all Secrets ans Folders 
    in a VAULT Hashicorp Repository.
    """
    folders_list, secrets_list = get_delete_informations(
        path, 
        client
    ) # Get the first folders and secrets in vault's root directory
    
    # Keep searching until no informations 
    # in folders_list and secrets_list.
    while (folders_list or secrets_list):
        for secret in secrets_list:
            client.delete(secret) # Delete the secret
            secrets_list.remove(secret)
        
        for folder in folders_list:
            folders_list.remove(folder)

            tmp_folders_list, tmp_secrets_list = get_delete_informations(
                folder, client
            ) # Search for other secrets and folders

            # Append secrets and folders in lists.
            folders_list.extend(tmp_folders_list)
            secrets_list.extend(tmp_secrets_list)


def export_to_vault(vault_url, vault_repo, ssl_verify=True):
    """
    Initial Script Function to export
    all KEEPASS File Data to a 
    VAULT Hashicorp Repository. 
    """
    exported_entries = CONF.ENTRIES_EXPORTED # Declare global variable used
    
    client = hvac.Client(
        url=vault_url, 
        token=CONF.TOKEN, 
        verify=ssl_verify
    ) # Connect to Vault Database

    vault_repo = clean_initial_repo(
        vault_repo
    ) # Clean Repository URL

    # Test and delete if Directory 
    # already exists in vault repository.
    if client.list(vault_repo):
        CONF.LOGGER.debug(
            '{}ROOT FOLDER ALREADY EXISTS: {}{}'.format(
                CONF.YELLOW_TERMINAL_COLOR, 
                CONF.TERMINAL_COLOR, 
                vault_repo
            )
        )

        if CONF.DELETE_EXISTING_REPOSITORY:
            CONF.LOGGER.debug(
                '{}DELETE ALL SECRETS AND FOLDERS ....{}: {}'.format(
                    CONF.RED_TERMINAL_COLOR, 
                    CONF.TERMINAL_COLOR, 
                    vault_repo
                )
            )

            recursive_delete(
                vault_repo,
                client
            ) # Delete all data recursively

            CONF.LOGGER.debug(
                '{}ALL REPO DATA DELETED SUCCESSFULLY{}: {}'.format(
                    CONF.GREEN_TERMINAL_COLOR, 
                    CONF.TERMINAL_COLOR, 
                    vault_repo
                )
            )
        else:
            CONF.SYS.excepthook = CONF.excepthook # Raise Errors without Treceback 
            raise Exception(
                "{}CAN'T COMPLETE EXPORT PROCESS, EITHER: {}\n".format(
                    CONF.RED_TERMINAL_COLOR, 
                    CONF.TERMINAL_COLOR
                )+"-DELETE ROOT FOLDER : YOU HAVE TO SPECIFY "+
                "<-d> IN COMMAND LINE.\n"+
                "-CHOOSE ANOTHER VAULT REPOSITORY URL."
            )

    complete_vault_url = '{}{}'.format(
        vault_url, 
        vault_repo
    ) # Complete vault directory URL

    CONF.LOGGER.debug(
        '{}CREATE NEW ROOT FOLDER ....{} : {}'.format(
            CONF.GREEN_TERMINAL_COLOR, 
            CONF.TERMINAL_COLOR, 
            complete_vault_url
        )
    )

    CONF.LOGGER.debug(
        '{}EXPORT ALL KEEPASS DATA TO VAULT....{} : {}'.format(
            CONF.BLUE_TERMINAL_COLOR, 
            CONF.TERMINAL_COLOR, 
            complete_vault_url
        )
    )

    entries = export_entries(
        CONF.KEEPASS_DB, 
        CONF.PASSWORD, 
        CONF.KEYFILE
    ) # Get Entries to be exported

    print_progress_bar(
        exported_entries, 
        len(entries), 
        prefix='Progress:', 
        suffix='Complete', 
        length=75
    ) # Initial call to print 0% progress
    
    
    ignored_indexes = [
        '_entry_name', '_path', 'Title' 
    ] # Declare indexes to be ignored

    for e in entries:
        cleaned_entry = {
            k: v for k, v in e.items() if k not in ignored_indexes
        } # Clean entries and ignore the ignored indexes

        entry_path = '{}/{}{}'.format(
            vault_repo,
            e['_path'] + '/' if e['_path'] else '',
            e['_entry_name']
        ) # Declare the entry's Vault Path

        entry_path = entry_path.encode(
            'ascii', 
            'ignore'
        ) # Encode entry and ignore if ascii can't be decoded

        if client.read(entry_path):
            next_entry_index = get_next_similar_entry_index(
                vault_url, 
                entry_path, 
                ssl_verify
            ) # There already is an entry at this path


            entry_path = '{} ({})'.format(
                entry_path, 
                next_entry_index
            ) # Declare the entry's new Vault Path
        
        client.write(
            entry_path, 
            **cleaned_entry 
        ) # Add Entry to Vault

        # Increment ENTRIES_EXPORTED var
        exported_entries += 1
        print_progress_bar(
            exported_entries, 
            len(entries), 
            prefix='Progress:', 
            suffix='Complete', 
            length=75
        ) # Print progress bar

    CONF.LOGGER.debug(
        '{}ALL KEEPASS DATA EXPORTED SUCCESSFULLY TO VAULT....{} : {}'.format(
            CONF.GREEN_TERMINAL_COLOR, 
            CONF.TERMINAL_COLOR, 
            complete_vault_url
        )
    )


if __name__ == '__main__':
    # Add argument parser. And All Arguments to be parsed.
    __parser__ = CONF.ARG_PARSER.ArgumentParser()

    __parser__.add_argument(
        '-p', '--password',
        required=True,
        help='Password to unlock the KeePass database'
    )
    __parser__.add_argument(
        '-f', '--keyfile',
        required=False,
        help='Keyfile to unlock the KeePass database'
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
        '-d', '--delete',
        action='store_true',
        default=True,
        required=False,
        help='Delete existing Vault Repository'
    )
    __parser__.add_argument(
        '-k', '--ssl-no-verify',
        action='store_true',
        default=True if CONF.OS.getenv('VAULT_SKIP_VERIFY', False) else False,
        required=False,
        help='Whether to skip TLS cert verification'
    )
    __parser__.add_argument(
        'KDBX',
        help='Path to the KeePass database'
    )
    __parser__.add_argument(
        '-aurl', '--authurl',
        required=True,
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

    PASSWORD = __args__.password # Get Password

    # Get keyfile name to build file directory
    CONF.KEYFILE = os.path.join(
        CONF.KEEPASS_DIRECTORY_FILES, 
        'keys', 
        __args__.keyfile
    ) if __args__.keyfile else None
    
    if __args__.KDBX:
        CONF.KEEPASS_DB = os.path.join(
            CONF.KEEPASS_DIRECTORY_FILES, 
            'keepass2vault', 
            __args__.KDBX
        ) # Get KeePass name and build file directory
    else:
        CONF.SYS.excepthook = CONF.excepthook # Raise Errors without Treceback 
        raise Exception(
            '{}Please provide your KEEPASS KDBX file.{}'.format(
                CONF.RED_TERMINAL_COLOR, 
                CONF.TERMINAL_COLOR
            )
        )        
    
    CONF.DELETE_EXISTING_REPOSITORY = \
        __args__.delete if __args__.delete else False # Get delete status

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
                __args__.vault+__args__.authurl
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
    # we can export KEEPASS V2 File content to a 
    # VAULT Hashicorp Repository.
    export_to_vault(
        vault_url=__args__.vault,
        vault_repo=__args__.repourl,
        ssl_verify=not __args__.ssl_no_verify
    )
