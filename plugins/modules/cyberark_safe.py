#!/usr/bin/python
# Copyright: (c) 2017, Ansible Project
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: cyberark_safe
short_description: Module for CyberArk Safe object creation, deletion, and
    modification using PAS Web Services SDK.
author:
    - CyberArk BizDev (@cyberark-bizdev)
    - Edward Nunez (@enunez-cyberark)
    - James Stutes (@jimmyjamcabd)
    - Lebas Jerome 
version_added: 1.0
description:
    - Creates a URI for adding, deleting, modifying a privileged safe
      within the Cyberark Vault.  The request uses the Privileged Safe
      Security Web Services SDK.


options:
    state:
        description:
            - Assert the desired state of the safe C(present) to create or
              update and safe object. Set to C(absent) for deletion of an
              account object.
        required: true
        default: present
        choices: [present, absent]
        type: str
    logging_level:
        description:
            - Parameter used to define the level of troubleshooting output to
              the C(logging_file) value.
        required: true
        choices: [NOTSET, DEBUG, INFO]
        type: str
    logging_file:
        description:
            - Setting the log file name and location for troubleshooting logs.
        required: false
        default: /tmp/ansible_cyberark.log
        type: str
    api_base_url:
        description:
            - A string containing the base URL of the server hosting CyberArk's
              Privileged Account Security Web Services SDK.
            - Example U(https://<IIS_Server_Ip>/PasswordVault/api/)
        required: true
        type: str
    validate_certs:
        description:
            - If C(false), SSL certificate chain will not be validated.  This
              should only set to C(true) if you have a root CA certificate
              installed on each node.
        required: false
        default: true
        type: bool
    cyberark_session:
        description:
            - Dictionary set by a CyberArk authentication containing the
              different values to perform actions on a logged-on CyberArk
              session, please see M(cyberark_authentication) module for an
              example of cyberark_session.
        required: true
        type: dict
    identified_by:
        description:
            - When an API call is made to Get Accounts, often times the default
              parameters passed will identify more than one account. This
              parameter is used to confidently identify a single account when
              the default query can return multiple results.
        required: false
        default: username,address,platform_id
        type: str
    safe:
        description:
            - The safe in the Vault where the privileged account is to be
              located.
        required: true
        type: str
    platform_id:
        description:
            - The PolicyID of the Platform that is to be managing the account
        required: false
        type: str
    address:
        description:
            - The address of the endpoint where the privileged account is
              located.
        required: false
        type: str
    name:
        description:
            - The ObjectID of the account
        required: false
        type: str
    secret_type:
        description:
            - The value that identifies what type of account it will be.
        required: false
        default: password
        choices: [password, key]
        type: str
    secret:
        description:
            - The initial password for the creation of the account
        required: false
        type: str
    new_secret:
        description:
            - The new secret/password to be stored in CyberArk Vault.
        type: str
    username:
        description:
            - The username associated with the account.
        required: false
        type: str
    secret_management:
        description:
            - Set of parameters associated with the management of the
              credential.
        required: false
        type: dict
        suboptions:
            automatic_management_enabled:
                description:
                    - Parameter that indicates whether the CPM will manage
                        the password or not.
                default: False
                type: bool
            manual_management_reason:
                description:
                    - String value indicating why the CPM will NOT manage
                        the password.
                type: str
            management_action:
                description:
                    - CPM action flag to be placed on the account object
                        for credential rotation.
                choices: [change, change_immediately, reconcile]
                type: str
            new_secret:
                description:
                    - The actual password value that will be assigned for
                        the CPM action to be taken.
                type: str
            perform_management_action:
                description:
                    - C(always) will perform the management action in
                        every action.
                    - C(on_create) will only perform the management action
                        right after the account is created.
                choices: [always, on_create]
                default: always
                type: str
    remote_machines_access:
        description:
            - Set of parameters for defining PSM endpoint access targets.
        required: false
        type: dict
        suboptions:
            remote_machines:
                description:
                    - List of targets allowed for this account.
                type: str
            access_restricted_to_remote_machines:
                description:
                    - Whether or not to restrict access only to specified
                        remote machines.
                type: bool
    platform_account_properties:
        description:
            - Object containing key-value pairs to associate with the account,
              as defined by the account platform. These properties are
              validated against the mandatory and optional properties of the
              specified platform's definition. Optional properties that do not
              exist on the account will not be returned here. Internal
              properties are not returned.
        required: false
        type: dict
        suboptions:
            KEY:
                description:
                    - Freeform key value associated to the mandatory or
                        optional property assigned to the specified
                        Platform's definition.
                aliases: [Port, ExtrPass1Name, database]
                type: str
"""

EXAMPLES = """
  collections:
    - cyberark.pas

  tasks:

    - name: Logon to CyberArk Vault using PAS Web Services SDK
      cyberark_authentication:
        api_base_url: "http://components.cyberark.local"
        validate_certs: no
        username: "bizdev"
        password: "Cyberark1"

    - name: Creating an Safe using the PAS WebServices SDK
      cyberark_safe:
        logging_level: DEBUG
        safe_name : "Test"
        number_of_days_retention : ""
        managing_cpm : ""
        description : ""
        address: "cyberark.local"  
        state: present
        cyberark_session: "{{ cyberark_session }}"
      register: cyberarkaction 


    - name: Logoff from CyberArk Vault
      cyberark_authentication:
        state: absent
        cyberark_session: "{{ cyberark_session }}"

"""
RETURN = """
changed:
    description:
        - Identify if the playbook run resulted in a change to the account in
          any way.
    returned: always
    type: bool
failed:
    description: Whether playbook run resulted in a failure of any kind.
    returned: always
    type: bool
status_code:
    description: Result HTTP Status code.
    returned: success
    type: int
    sample: "200, 201, -1, 204"
result:
    description: A json dump of the resulting action.
    returned: success
    type: complex
    contains:
        address:
            description:
                - The adress of the endpoint where the privileged account is
                  located.
            returned: successful addition and modification
            type: str
            sample: dev.local
        createdTime:
            description:
                - Timeframe calculation of the timestamp of account creation.
            returned: successful addition and modification
            type: int
            sample: "1567824520"
        id:
            description: Internal ObjectID for the account object identified
            returned: successful addition and modification
            type: int
            sample: "25_21"
        name:
            description: The external ObjectID of the account
            returned: successful addition and modification
            type: str
            sample:
                - Operating System-WinServerLocal-cyberark.local-administrator
        platformAccountProperties:
            description:
                - Object containing key-value pairs to associate with the
                  account, as defined by the account platform.
            returned: successful addition and modification
            type: complex
            contains:
                KEY VALUE:
                    description:
                        - Object containing key-value pairs to associate with the
                          account, as defined by the account platform.
                    returned: successful addition and modification
                    type: str
                    sample:
                        - "LogonDomain": "cyberark"
                        - "Port": "22"
        platformId:
            description:
                - The PolicyID of the Platform that is to be managing the
                  account.
            returned: successful addition and modification
            type: str
            sample: WinServerLocal
        safeName:
            description:
                - The safe in the Vault where the privileged account is to
                  be located.
            returned: successful addition and modification
            type: str
            sample: Domain_Admins
        secretManagement:
            description:
                - Set of parameters associated with the management of
                  the credential.
            returned: successful addition and modification
            type: complex
            sample:
                automaticManagementEnabled:
                    description:
                        - Parameter that indicates whether the CPM will manage
                          the password or not.
                    returned: successful addition and modification
                    type: bool
                lastModifiedTime:
                    description:
                        - Timeframe calculation of the timestamp of account
                          modification.
                    returned: successful addition and modification
                    type: int
                    sample: "1567824520"
                manualManagementReason:
                    description:
                    returned: if C(automaticManagementEnabled) is set to false
                    type: str
                    sample: This is a static account
        secretType:
            description:
                - The value that identifies what type of account it will be
            returned: successful addition and modification
            type: list
            sample:
                - key
                - password
        userName:
            description: The username associated with the account
            returned: successful addition and modification
            type: str
            sample: administrator
"""


from ansible.module_utils._text import to_text
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url
from ansible.module_utils.six.moves.urllib.error import HTTPError
import urllib

import json
try:
    import httplib
except ImportError:
    # Python 3
    import http.client as httplib
import logging

_empty = object()

ansible_specific_parameters = [
    "state",
    "api_base_url",
    "validate_certs",
    "cyberark_session",
    "identified_by",
    "logging_level",
    "logging_file", 
]

cyberark_fixed_properties = [    
    "lastModifiedTime",
    "safeName",    
]

removal_value = "NO_VALUE"

cyberark_reference_fieldnames = {   
    "safe_name": "safeName",
    "platform_idp": "latformId",
    "olac_enable": "OLACEnabled",     
    "description": "Description",
    "managing_cpm": "ManagingCPM",
    "number_of_days_retention": "NumberOfDaysRetention",
    "member_safe_properties" : "MemberSafeProperties",
    "search_in" : "SearchIn",
    "member_type": "MemberType",
    "member_name": "MemberName",
    "member_ship_expiration_date": "MembershipExpirationDate",
    "permissions": "Permissions",
    "use_accounts": "UseAccounts",
    "retrieve_accounts": "RetrieveAccounts",
    "list_accounts": "ListAccounts",
    "add_accounts": "AddAccounts",
    "update_account_content": "UpdateAccountContent",
    "update_account_properties": "UpdateAccountProperties",
    "initiate_cpma_account_management_operations": "InitiateCPMAccountManagementOperations",
    "specify_next_account_content": "SpecifyNextAccountContent",
    "rename_accounts": "RenameAccounts",
    "delete_accounts": "DeleteAccounts",
    "unlock_accounts": "UnlockAccounts",
    "manage_safe": "ManageSafe",
    "manage_safe_members": "ManageSafeMembers",
    "backup_safe": "BackupSafe",
    "view_audit_log": "ViewAuditLog",
    "view_safe_members": "ViewSafeMembers",
    "requests_authorization_level1": "RequestsAuthorizationLevel1",
    "access_without_confirmation": "AccessWithoutConfirmation",
    "create_folders": "CreateFolders",
    "delete_folders": "DeleteFolders",
    "move_accounts_and_folders" : "MoveAccountsAndFolders",
}

ansible_reference_fieldnames = {
    "OLACEnabled": "olac_enable",
    "safeName": "safe_name",
    "platformId": "platform_id",
    "Description": "description",
    "ManagingCPM": "managing_cpm",
    "NumberOfDaysRetention": "number_of_days_retention",
    "MemberSafeProperties" : "member_safe_properties",
    "SearchIn" : "search_in",
    "MemberType": "member_type",
    "MemberName": "member_name", 
    "MembershipExpirationDate": "member_ship_expiration_date",
    "Permissions": "permissions",
    "UseAccounts": "use_accounts",
    "RetrieveAccounts": "retrieve_accounts",
    "ListAccounts": "list_accounts",
    "AddAccounts": "add_accounts",
    "UpdateAccountContent": "update_account_content",
    "UpdateAccountProperties": "update_account_properties",
    "InitiateCPMAccountManagementOperations": "initiate_cpma_account_management_operations",
    "SpecifyNextAccountContent": "specify_next_account_content",
    "RenameAccounts": "rename_accounts",
    "DeleteAccounts": "delete_accounts",
    "UnlockAccounts": "unlock_accounts",
    "ManageSafe": "manage_safe",
    "ManageSafeMembers": "manage_safe_members",
    "BackupSafe": "backup_safe",
    "ViewAuditLog": "view_audit_log",
    "ViewSafeMembers": "view_safe_members",
    "RequestsAuthorizationLevel1": "requests_authorization_level",
    "AccessWithoutConfirmation": "access_without_confirmation",
    "CreateFolders": "create_folders",
    "DeleteFolders": "delete_folders",
    "MoveAccountsAndFolders" : "move_accounts_and_folders",
}


def equal_value(existing, parameter):
    if isinstance(existing, str):
        return existing == str(parameter)
    elif isinstance(parameter, str):
        return str(existing) == parameter
    else:
        return existing == parameter


def update_safe(module, existing_safe):
    
    """"
    {
	"member": {
		"MembershipExpirationDate":"<MM\DD\YY or empty for no expiration>",
		"Permissions":<User’s permissions in the Safe>
		[
			{"Key":"UseAccounts", "Value":<true/false>},
			{"Key":"RetrieveAccounts", "Value":<true/false>},
			{"Key":"ListAccounts", "Value":<true/false>},
			{"Key":"AddAccounts", "Value":<true/false>},
			{"Key":"UpdateAccountContent", "Value":<true/false>},
			{"Key":"UpdateAccountProperties", "Value":<true/false>},
			{"Key":"InitiateCPMAccountManagementOperations", "Value":<true/false>},
			{"Key":"SpecifyNextAccountContent", "Value":<true/false>},
			{"Key":"RenameAccounts", "Value":<true/false>},
			{"Key":"DeleteAccounts", "Value":<true/false>},
			{"Key":"UnlockAccounts", "Value":<true/false>},
			{"Key":"ManageSafe", "Value":<true/false>},
			{"Key":"ManageSafeMembers", "Value":<true/false>},
			{"Key":"BackupSafe", "Value":<true/false>},
			{"Key":"ViewAuditLog", "Value":<true/false>},
			{"Key":"ViewSafeMembers", "Value":<true/false>},
			{"Key":"RequestsAuthorizationLevel", "Value":<0/1/2>},
			{"Key":"AccessWithoutConfirmation", "Value":<true/false>},
			{"Key":"CreateFolders", "Value":<true/false>},
			{"Key":"DeleteFolders", "Value":<true/false>},
			{"Key":"MoveAccountsAndFolders", "Value":<true/false>}
		]
	    }
    }    
    
    """

    logging.debug("Updating Safes")

    cyberark_session = module.params["cyberark_session"]
    api_base_url = cyberark_session["api_base_url"]
    validate_certs = cyberark_session["validate_certs"]

    # Prepare result, end_point, and headers
    result = {"result existing safe ": existing_safe}
    changed = False
    last_status_code = -1

    #logging.debug("Updating Safes %s" % existing_safe["id"] )
    logging.debug("Updating Safes %s" % existing_safe )

    HTTPMethod = "POST"
    end_point = "/PasswordVault/api/Safes/%s/Members" % existing_safe["safeName"]

    headers = {
        "Content-Type": "application/json",
        "Authorization": cyberark_session["token"],
    }

    #payload = {}
    payload = {"Operations": []}
    
    # Determining whether to add or update safe properties
    for parameter_name in module.params.keys():
        if (
            parameter_name not in ansible_specific_parameters
            and module.params[parameter_name] is not None
        ):
            module_parm_value = module.params[parameter_name]
            cyberark_property_name = referenced_value(
                parameter_name,
                cyberark_reference_fieldnames,
                default=parameter_name
            )
            existing_safe_value = referenced_value(
                cyberark_property_name,
                existing_safe,
                keys=existing_safe.keys()
            )
            if cyberark_property_name not in cyberark_fixed_properties:
                if module_parm_value is not None and isinstance(
                    module_parm_value, dict
                ):
                    # Internal child values
                    replacing = {}
                    adding = {}
                    removing = {}
                    for child_parm_name in module_parm_value.keys():
                        nested_parm_name = "%s.%s" % (
                            parameter_name,
                            child_parm_name)
                        if (
                            nested_parm_name not in ansible_specific_parameters
                        ):
                            child_module_parm_value = module_parm_value[
                                child_parm_name
                            ]
                            child_cyberark_property_name = referenced_value(
                                child_parm_name,
                                cyberark_reference_fieldnames,
                                default=child_parm_name,
                            )
                            child_existing_safe_value = referenced_value(
                                child_cyberark_property_name,
                                existing_safe_value,
                                existing_safe_value.keys()
                                if existing_safe_value is not None
                                else {},
                            )
                            path_value = "/%s/%s" % (
                                cyberark_property_name,
                                child_cyberark_property_name,
                            )
                            if child_existing_safe_value is not None:
                                logging.debug(
                                    ("child_module_parm_value: %s "
                                     "child_existing_safe_value=%s path=%s")%
                                    (
                                        child_module_parm_value,
                                        child_existing_safe_value,
                                        path_value,
                                    )
                                )
                                if child_module_parm_value == removal_value:
                                    removing.update(
                                        {
                                            child_cyberark_property_name:
                                            child_existing_safe_value
                                        }
                                    )
                                elif (
                                    child_module_parm_value is not None
                                    and not equal_value(
                                        child_existing_safe_value,
                                        child_module_parm_value,
                                    )
                                ):
                                    # Updating a property
                                    replacing.update(
                                        {
                                            child_cyberark_property_name:
                                            child_module_parm_value
                                        }
                                    )
                            elif (
                                child_module_parm_value is not None
                                and child_module_parm_value != removal_value
                            ):
                                # Adding a property value
                                adding.update(
                                    {                                        
                                          child_cyberark_property_name:
                                          child_module_parm_value                                        
                                    }
                                )
                            logging.debug("Adding => %s" % adding )
                            logging.debug(
                                "parameter_name=%s  value=%s existing=%s"%
                                (
                                    path_value,
                                    child_module_parm_value,
                                    child_existing_safe_value,
                                )
                            )

                    logging.debug("Debug Adding => %s", json.dumps(adding))
                    logging.debug("Debug Keys => %s", len(adding.keys()))
                    logging.debug("Debug parameter => %s", module_parm_value )
                    # Processing child operations
                    if len(adding.keys()) > 0:                        
                        payload["Operations"].append({
                            "MemberName": module.params['member_name'],
                            "SearchIn": module.params['search_in'] ,
                            "MembershipExpirationDate": module.params['member_ship_expiration_date'],
                            "Permissions" : adding,     
                        })
                        logging.debug("Debug POST => %s %s", (end_point,json.dumps(payload)) )   
                        
                    if len(replacing.keys()) > 0:
                       payload["Operations"].append({
                            "MemberName": module.params['member_name'],
                            "SearchIn": module.params['search_in'] ,
                            "MembershipExpirationDate": module.params['member_ship_expiration_date'],
                            "Permissions" : replacing,     
                        }) 
                        
                    if len(removing) > 0:
                        payload["Operations"].append({
                            "MemberName": module.params['member_name'],
                            "SearchIn": module.params['search_in'] ,
                            "MembershipExpirationDate": module.params['member_ship_expiration_date'],
                            "Permissions" : removing,     
                        })
                else:
                    if existing_safe_value is not None:
                        logging.debug("to do")
                        #if module_parm_value == removal_value:
                        #    payload["Operations"].append(
                        #        {"op": "remove", "path": "/%s" %
                        #            cyberark_property_name}
                        #    )
                        #elif not equal_value(
                        #    existing_safe_value,
                        #    module_parm_value
                        #):
                        #    # Updating a property
                        #    payload["Operations"].append(
                        #        {
                        #            "op": "replace",
                        #            "value": module_parm_value,
                        #            "path": "/%s" % cyberark_property_name,
                        #        }
                        #    )
                    elif module_parm_value != removal_value:
                        logging.debug("to do")
                        # Adding a property value
                        #payload["Operations"].append(
                        #    {
                        #        "op": "add",
                        #        "value": module_parm_value,
                        #        "path": "/%s" % cyberark_property_name,
                        #    }
                        #)
                    logging.debug(
                        "parameter_name=%s  value=%s existing=%s"%
                        (
                            parameter_name, module_parm_value,
                            existing_safe_value
                        )
                    )

    #if len(payload["Operations"]) != 0:
    if len(payload) != 0:    
        if module.check_mode:
            logging.debug("Proceeding with Update Safe (CHECK_MODE)")
            logging.debug("member => %s", json.dumps(payload))
            result = {"result": existing_safe}
            changed = True
            last_status_code = -1
        else:            
            logging.debug(
                "Processing invidual operations (%d) => %s%s %s ",
                len(payload),
                api_base_url,
                end_point,
                json.dumps(payload)                
            )
            #import ipdb;ipdb.set_trace()
            for operation in payload["Operations"]:
                individual_payload = operation
                try:
                    logging.debug(" Query ==> %s", json.dumps(operation))
                    response = open_url(
                        api_base_url + end_point,
                        method=HTTPMethod,
                        headers=headers,
                        data=json.dumps(individual_payload),                        
                        validate_certs=validate_certs,
                    )

                    result = {"result": json.loads(response.read())}
                    logging.debug("result => %s", json.loads(response.read()))
                    logging.debug("ERROR result => %s", dir(response.strerror()))
                    logging.debug("HTTP code %s", response.getcode() )
                    changed = True
                    last_status_code = response.getcode()

                #                return (True, result, response.getcode())

                except (HTTPError, httplib.HTTPException) as http_exception:
                    logging.debug("HTTPError result => %s", http_exception.msg)                    
                    logging.debug("HTTPError code %s", http_exception.code )
                    
                    if isinstance(http_exception, HTTPError):
                        res = json.load(http_exception)
                    else:
                        res = to_text(http_exception)
                    
                    if http_exception.code == 409 and 'Conflict' in http_exception.msg:
                      logging.debug("Error already exist => %s", json.dumps(res))                     
                      return (False, None, http_exception.code)
                    
                    elif http_exception.code == 404 and 'Not Found' in http_exception.msg: 
                      logging.debug("Not found  => %s", json.dumps(res))
                      return (False, None, http_exception.code) 
                    
                    elif http_exception.code == 500:
                      logging.debug("Error 500  => %s", json.dumps(res))
                      return (False, None, http_exception.code)

                    #module.exit_json(changed=True, result=http_exception.msg, status_code=http_exception.code)  


                    module.fail_json(
                        msg=(
                            "Error while performing update_safe."
                            "Please validate parameters provided."
                            "\n*** end_point=%s%s\n ==> %s"
                            % (api_base_url, end_point, res)
                        ),
                        payload=individual_payload,
                        headers=headers,
                        status_code=http_exception.code,
                    )

                except Exception as unknown_exception:

                    module.fail_json(
                        msg=(
                            "Unknown error while performing update_safe."
                            "\n*** end_point=%s%s\n%s"
                            % (
                                api_base_url, end_point,
                                to_text(unknown_exception)
                            )
                        ),
                        payload=individual_payload,
                        headers=headers,
                        status_code=-1,
                    )

    return (changed, result, last_status_code)


def add_safe(module):

    logging.debug("Adding Safe")

    cyberark_session = module.params["cyberark_session"]
    api_base_url = cyberark_session["api_base_url"]
    validate_certs = cyberark_session["validate_certs"]

    # Prepare result, end_point, and headers
    result = {}
    HTTPMethod = "POST"
    end_point = "/PasswordVault/api/Safes"

    headers = {
        "Content-Type": "application/json",
        "Authorization": cyberark_session["token"],
    }

    payload = {"safeName": module.params["safe_name"]}

    for parameter_name in module.params.keys():
        if (
            parameter_name not in ansible_specific_parameters
            and module.params[parameter_name] is not None
        ):
            cyberark_property_name = referenced_value(
                parameter_name,
                cyberark_reference_fieldnames,
                default=parameter_name
            )
            logging.debug("cyberark_property_name =%s", cyberark_property_name)
            if isinstance(module.params[parameter_name], dict):
                payload[cyberark_property_name] = {}
                for dict_key in module.params[parameter_name].keys():
                    cyberark_child_property_name = referenced_value(
                        dict_key,
                        cyberark_reference_fieldnames,
                        default=dict_key
                    )
                    logging.debug(
                        ("parameter_name =%s.%s cyberark_property_name=%s "
                         "cyberark_child_property_name=%s"),
                        parameter_name,
                        dict_key,
                        cyberark_property_name,
                        cyberark_child_property_name,
                    )
                    if (
                        parameter_name + "." + dict_key
                        not in ansible_specific_parameters
                        and module.params[parameter_name][dict_key] is not None
                    ):
                        payload[cyberark_property_name][
                            cyberark_child_property_name
                        ] = deep_get(
                            module.params[parameter_name],
                            dict_key,
                            _empty,
                            False
                        )
            else:
                if parameter_name not in cyberark_reference_fieldnames:
                    module_parm_value = deep_get(
                        module.params, parameter_name, _empty, False
                    )
                    if (
                        module_parm_value is not None
                        and module_parm_value != removal_value
                    ):
                        payload[
                            parameter_name
                        ] = module_parm_value  # module.params[parameter_name]
                else:
                    module_parm_value = deep_get(
                        module.params, parameter_name, _empty, True
                    )
                    if (
                        module_parm_value is not None
                        and module_parm_value != removal_value
                    ):
                        payload[
                            cyberark_reference_fieldnames[parameter_name]
                        ] = module_parm_value  # module.params[parameter_name]
            logging.debug("parameter_name =%s", parameter_name)

    logging.debug("Add Safes Payload => %s", json.dumps(payload))

    try:

        if module.check_mode:
            logging.debug("Proceeding with Add Safe (CHECK_MODE)")
            return (True, {"result": None}, -1)
        else:
            logging.debug("Proceeding with Add Safe")
            response = open_url(
                api_base_url + end_point,
                method=HTTPMethod,
                headers=headers,
                data=json.dumps(payload),
                validate_certs=validate_certs,
            )

            result = {"result": json.loads(response.read())}

            return (True, result, response.getcode())

    except (HTTPError, httplib.HTTPException) as http_exception:

        if isinstance(http_exception, HTTPError):
            res = json.load(http_exception)
        else:
            res = to_text(http_exception)

        if http_exception.code == 409:
          logging.debug("Error already exist => %s", json.dumps(res))
          logging.debug("%s", http_exception.code)
          module.exit_json(changed=True, result=result, status_code=http_exception.code)
        else:  
          module.fail_json(
              msg=(
                  "Error while performing add_safe."
                  "Please validate parameters provided."
                  "\n*** end_point=%s%s\n ==> %s" % (
                      api_base_url,
                      end_point,
                      res
                  )
              ),
              payload=payload,
              headers=headers,
              status_code=http_exception.code,
          )

    except Exception as unknown_exception:

        module.fail_json(
            msg=(
                "Unknown error while performing add_safe."
                "\n*** end_point=%s%s\n%s"
                % (api_base_url, end_point, to_text(unknown_exception))
            ),
            payload=payload,
            headers=headers,
            status_code=-1,
        )


def delete_safe(module, existing_safe):

    if module.check_mode:
        logging.debug("Deleting Safe (CHECK_MODE)")
        return (True, {"result": None}, -1)
    else:
        logging.debug("Deleting Safe")

        cyberark_session = module.params["cyberark_session"]
        api_base_url = cyberark_session["api_base_url"]
        validate_certs = cyberark_session["validate_certs"]

        # Prepare result, end_point, and headers
        result = {}
        HTTPMethod = "DELETE"
        end_point = "/PasswordVault/api/Safes/%s" % existing_safe["safeName"]

        headers = {
            "Content-Type": "application/json",
            "Authorization": cyberark_session["token"],
        }

        try:

            response = open_url(
                api_base_url + end_point,
                method=HTTPMethod,
                headers=headers,
                validate_certs=validate_certs,
            )

            result = {"result": None}

            return (True, result, response.getcode())

        except (HTTPError, httplib.HTTPException) as http_exception:

            if isinstance(http_exception, HTTPError):
                res = json.load(http_exception)
            else:
                res = to_text(http_exception)

            module.fail_json(
                msg=(
                    "Error while performing delete_safe."
                    "Please validate parameters provided."
                    "\n*** end_point=%s%s\n ==> %s" % (
                        api_base_url,
                        end_point,
                        res
                    )
                ),
                headers=headers,
                status_code=http_exception.code,
            )

        except Exception as unknown_exception:

            module.fail_json(
                msg=(
                    "Unknown error while performing delete_safe."
                    "\n*** end_point=%s%s\n%s"
                    % (api_base_url, end_point, to_text(unknown_exception))
                ),
                headers=headers,
                status_code=-1,
            )



def referenced_value(field, dct, keys=None, default=None):
    return dct[field] if field in (
        keys if keys is not None else dct
    ) else default


def deep_get(dct, dotted_path, default=_empty, use_reference_table=True):
    logging.debug("Function deep_get  %s", dotted_path) 
    logging.debug("Function deep_get  %s", dct)
    result_dct = {}
    for key in dotted_path.split("."):
        try:
            key_field = key
            if use_reference_table:
                key_field = referenced_value(
                    key, cyberark_reference_fieldnames, default=key
                )
            logging.debug("Key Field  %s", key_field)
            if len(result_dct.keys()) == 0:  # No result_dct set yet
                result_dct = dct

            logging.debug(
                "keys=%s key_field=>%s   key=>%s",
                ",".join(result_dct.keys()),
                key_field,
                key
            )
            result_dct = (
                result_dct[key_field]
                if key_field in result_dct.keys()
                else result_dct[key]
            )
            if result_dct is None:
                return default

        except KeyError as e:
            logging.debug("KeyError %s", to_text(e))
            if default is _empty:
                raise
            return default
    return result_dct


def get_safe(module):

    logging.debug("Finding safe")

    identified_by_fields = module.params["identified_by"].split(",")
    #logging.debug("Identified_by: %s", json.dumps(identified_by_fields))
    logging.debug("Safe parameters => %s", module.params)
    logging.debug("Safe Identified by  => %s", identified_by_fields)
    safe_filter = (
        urllib.parse.quote("safeName eq ") + urllib.parse.quote(module.params["safe_name"])
        if "safe_name" in module.params and module.params["safe_name"] is not None
        else None
    )
    #search_string = None
    #for field in identified_by_fields:
    #    if field not in ansible_specific_parameters:
    #        search_string = "%s%s" % (
    #            search_string + " " if search_string is not None else "",
    #            deep_get(module.params, field, "NOT FOUND", False),
    #        )

    #logging.debug("Search_String => %s", search_string)
    logging.debug("Safe Filter => %s", safe_filter)

    cyberark_session = module.params["cyberark_session"]
    api_base_url = cyberark_session["api_base_url"]
    validate_certs = cyberark_session["validate_certs"]

    end_point = None
    #if search_string is not None and safe_filter is not None:
    #    end_point = "/PasswordVault/api/Safes?filter=%s&search=%s" % (
   #         safe_filter,
    #        urllib.parse.quote(search_string.lstrip()),
   #     )
    #elif search_string is not None:
   #     end_point = (
    #        "/PasswordVault/api/Safes?search=%s"
    #    ) % (search_string.lstrip())
   # else:
   #     end_point = "/PasswordVault/api/Safes?filter=%s" % (safe_filter)
    end_point = ("/PasswordVault/api/Safes?search=%s") % (module.params["safe_name"].lstrip())
    #Send_point = "/PasswordVault/api/Safes?filter=%s" % (safe_filter)
    logging.debug("End Point => %s", end_point)

    headers = {"Content-Type": "application/json"}
    headers["Authorization"] = cyberark_session["token"]

    try:

        logging.debug("Executing: " + api_base_url + end_point)
        response = open_url(
            api_base_url + end_point,
            method="GET",
            headers=headers,
            validate_certs=validate_certs,
        )

        result_string = response.read()
        safes_data = json.loads(result_string)

        logging.debug("RESULT => %s", json.dumps(safes_data))        
        if "Total" in safes_data and safes_data["Total"] == 0:
            logging.debug("Result  => %s", safes_data["Total"])
            return (False, None, response.getcode())        
        elif "count" in safes_data and safes_data["count"] == 0: 
            logging.debug("Result  => %s", safes_data["count"])
            return (False, None, response.getcode())
        else:
            how_many = 0
            first_record_found = None
            
            logging.debug("Result  => %s", safes_data["value"][0])
            for safe_record in safes_data["value"]:
                logging.debug("Acct Record => %s", json.dumps(safe_record))
                found = False
                for field in identified_by_fields:
                    logging.debug("Field => %s", field)
                    try:
                      record_field_value = deep_get(
                          safe_record,
                          field,
                          "NOT FOUND"
                      )
                      logging.debug(
                          (
                              "Comparing field %s | record_field_name=%s  "
                              "record_field_value=%s   module.params_value=%s"
                          ),
                          field,
                          field,
                          record_field_value,
                          deep_get(module.params, field, "NOT FOUND")
                      )
                    except Exception as deep_exception:
                       logging.debug("Error deep function  => %s", deep_exception)

                    logging.debug("Record Field Value  => %s => %s", record_field_value ,deep_get(module.params,field,"NOT FOUND",False) )
                    if (
                        record_field_value != "NOT FOUND"
                        #and (
                        #    record_field_value
                        #    == deep_get(
                        #        module.params,
                        #        field,
                        #        "NOT FOUND",
                        #        False
                        #    )
                        #)
                    ):
                        found = True
                        logging.debug("found  => %b", found)
                    else:
                        found = False
                        logging.debug("found  => %b", found)
                        break
                if found:
                    how_many = how_many + 1
                    if first_record_found is None:
                        first_record_found = safe_record

            logging.debug(
                "How Many: %d  First Record Found => %s",
                how_many,
                json.dumps(first_record_found)
            )
            if how_many > 1:  # too many records found
                module.fail_json(
                    msg=(
                        "Error while performing get_safe. "
                        "Too many rows (%d) found matching your criteria!"
                    ) % how_many
                )
            else:
                return (how_many == 1, first_record_found, response.getcode())

    except (HTTPError, httplib.HTTPException) as http_exception:

        if http_exception.code == 404:
            logging.debug("Error 404 => %s", json.dumps(http_exception.code))
            return (False, None, http_exception.code)
        else:
            module.fail_json(
                msg=(
                    "Error while performing get_safe."
                    "Please validate parameters provided."
                    "\n*** end_point=%s%s\n ==> %s"
                    % (api_base_url, end_point, to_text(http_exception))
                ),
                headers=headers,
                status_code=http_exception.code,
            )

    except Exception as unknown_exception:

        module.fail_json(
            msg=(
                "Unknown error while performing get_safe."
                "\n*** end_point=%s%s\n%s"
                % (api_base_url, end_point, to_text(unknown_exception))
            ),
            headers=headers,
            status_code=-1,
        )


def main():

    fields = {
        "state": {
            "type": "str",
            "choices": ["present", "absent","update","search"],
            "default": "absent",
        },
        "logging_level": {
            "type": "str",
            "choices": ["NOTSET", "DEBUG", "INFO"]
        },
        "logging_file": {
            "type": "str",
            "default": "/tmp/ansible_cyberark.log"
        },
        "identified_by": {
            "required": False,
            "type": "str",
            "default": "safe_name",
        },
        "member_safe_properties": {"required": False, "type": "dict"},
        "member_ship_expiration_date" : {"required": False, "type": "str", "default": ""},
        "member_name" : {"required": False, "type": "str","default": ""},
        "search_in" : {"required": False, "type": "str", "default": ""}, 
        "api_base_url": {"type": "str"},
        "number_of_days_retention" : {"type": "str", "default": "365"},
        "managing_cpm" : {"type": "str", "default": "PasswordManager"},
        "validate_certs": {"type": "bool", "default": "true"},
        "description" : {"required": True, "type": "str"},
        "cyberark_session": {"required": True, "type": "dict", "no_log": True},        
        "safe_name": {"required": True, "type": "str"}
    }

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)

    if module.params["logging_level"] is not None:
        logging.basicConfig(
            filename=module.params["logging_file"],
            level=module.params["logging_level"]
        )

    logging.info("Starting Module")

    state = module.params["state"]

    (found, safe_record, status_code) = get_safe(module)

    logging.debug(
        "Safe was %s, status_code=%s",
        "FOUND" if found else "NOT FOUND",
        status_code
    )
    logging.debug("SAFE =>%s", safe_record ) 
    changed = False
    result = {"result": safe_record}

    if state == "present":
        if found:  # Safe already exists
            (changed, result, status_code) = update_safe(module,safe_record)
        else:  # Safe does not exist
            (changed, result, status_code) = add_safe(module)       

        logging.debug("Result=>%s", json.dumps(result))       

    elif found and state == "absent":
        (changed, result, status_code) = delete_safe(module, safe_record)
    elif found and state == "update":
        (changed, result, status_code) = update_safe(module, safe_record)
    elif found and state == "search":
        module.exit_json(changed=changed, result=result, status_code=status_code)

    module.exit_json(changed=found, result=safe_record, status_code=status_code)


if __name__ == "__main__":
    main()
