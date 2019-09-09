#!/usr/bin/python
# Copyright: (c) 2017, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: cyberark_add_account
short_description: Module for CyberArk Account object modification using PAS Web Services SDK
author: CyberArk BizDev Tech (@enunez-cyberark, @cyberark-bizdev, @erasmix @jimmyjamcabd)
version_added: 2.4
description:
    - Authenticates to CyberArk Vault using Privileged Account Security Web Services SDK and
      creates a session fact that can be used by other modules. It returns an Ansible fact
      called I(cyberark_session). Every module can use this fact as C(cyberark_session) parameter.

options:
  account:
    safe:
    platformID:
    address:
    accountName:
    password:
    username:
    disableAutoMgmt:
    disableAutoMgmtReason:
  groupName:
  groupPlatformID:
    properties:
      Key:Port,Value:
      Key:ExtraPass1Name,Value:
      Key:ExtraPass1Folder,Value:
      Key:ExtraPass1Safe,Value:
      Key:Extrapass3Name,Value
      Key:ExtraPass3Folder,Value:
      Key:ExtraPass3Safe,Value:
'''

EXAMPLES = '''
- name: Logon to CyberArk Vault using PAS Web Services SDK
  cyberark_authentication:
    api_base_url: "https://components.cyberark.local"
    use_shared_logon_authentication: true

- name: Add account to CyberArk Vault
  cyberark_add_account
    account:
      safe: "target safe name"
      platformID: "existing platform ID"
      address: "target address"
      password: "account password"
      username: "target account username"

'''
RETURN = '''


status_code:
    description: Account was added successfully
    returned: success
    type: int
    sample: 201
'''

from ansible.module_utils._text import to_text
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url
from ansible.module_utils.six.moves.urllib.error import HTTPError
import json
import urllib
try:
    import httplib
except ImportError:
    # Python 3
    import http.client as httplib
    
import sys
import logging

_empty = object()
ansible_specific_parameters = ["state", "api_base_url", "validate_certs", "cyberark_session", "identified_by", "logging_level", "logging_file"]
cyberark_nonremovable_properties = ["createdTime", "id", "name", "lastModifiedTime", "safeName", "secretType"]
removal_value = "NO_VALUE"

cyberark_reference_fieldnames = {
    "username" : "userName",
    "safe": "safeName",
    "platform_id": "platformId",
    "secret_type": "secretType",
    "platform_account_properties": "platformAccountProperties",
    "secret_management": "secretManagement",
    "manual_management_reason": "manualManagementReason",
    "automatic_management_enabled": "automaticManagementEnabled"
}

ansible_reference_fieldnames = {
    "userName" : "username",
    "safeName": "safe",
    "platformId": "platform_id",
    "secretType": "secret_type",
    "platformAccountProperties": "platform_account_properties",
    "secretManagement": "secret_management",
    "manualManagementReason": "manual_management_reason",
    "automaticManagementEnabled": "automatic_management_enabled"
}


def update_account(module, existing_account):
    
    logging.debug("Updating Account")

    cyberark_session = module.params["cyberark_session"]
    api_base_url = cyberark_session["api_base_url"]
    validate_certs = cyberark_session["validate_certs"]
    state = module.params["state"]

    # Prepare result, end_point, and headers
    result = {}
    HTTPMethod = "PATCH"
    end_point = "/PasswordVault/api/Accounts/%s" % existing_account["id"]

    headers = {'Content-Type': 'application/json',
               "Authorization": cyberark_session["token"]}
    
    payload = {"Operations": []}

    # Determining whether to add or update properties
    for parameter_name in module.params.keys():
        if parameter_name not in ansible_specific_parameters and module.params[parameter_name] is not None:
            module_parm_value = module.params[parameter_name]
            cyberark_property_name = cyberark_reference_fieldnames[parameter_name] if parameter_name in cyberark_reference_fieldnames else parameter_name
            existing_account_value = existing_account[cyberark_property_name] if cyberark_property_name in existing_account.keys() else None
            
            if isinstance(module_parm_value, dict):
                for child_parm_name in module_parm_value.keys():
                    child_module_parm_value = module_parm_value[child_parm_name]
                    child_cyberark_property_name = cyberark_reference_fieldnames[child_parm_name] if child_parm_name in cyberark_reference_fieldnames else child_parm_name
                    child_existing_account_value = existing_account_value[child_cyberark_property_name] if child_cyberark_property_name in existing_account_value.keys() else None
                    if child_existing_account_value is not None:
                        if child_module_parm_value == removal_value:
                            payload["Operations"].append({"op": "remove", "path": "/%s/%s" % (cyberark_property_name, child_cyberark_property_name)})
                        elif child_existing_account_value != child_module_parm_value:
                            # Updating a property
                            payload["Operations"].append({"op": "replace", "value": child_module_parm_value, "path": "/%s/%s" % (cyberark_property_name, child_cyberark_property_name)})
                    elif child_module_parm_value != removal_value:
                        # Adding a property value
                        payload["Operations"].append({"op": "add", "value": child_module_parm_value, "path": "/%s/%s" % (cyberark_property_name, child_cyberark_property_name)})
            else:
                if existing_account_value is not None:
                    if module_parm_value == removal_value:
                        payload["Operations"].append({"op": "remove", "path": "/%s/%s" % (cyberark_property_name, child_cyberark_property_name)})
                    elif existing_account_value != module_parm_value:
                        # Updating a property
                        payload["Operations"].append({"op": "replace", "value": module_parm_value, "path": "/%s" % cyberark_property_name})
                elif module_parm_value != removal_value:
                    # Adding a property value
                    payload["Operations"].append({"op": "add", "value": module_parm_value, "path": "/%s" % cyberark_property_name})
                logging.debug("parameter_name=%s  value=%s existing=%s" % (parameter_name, module_parm_value, existing_account_value))
                            
    if (len(payload["Operations"]) == 0):
        return(False, existing_account, -1)
    else:
        logging.debug("Operations => %s" % json.dumps(payload))
        try:
    
           response = open_url(
               api_base_url + end_point,
               method=HTTPMethod,
               headers=headers,
               data=json.dumps(payload["Operations"]),
               validate_certs=validate_certs)
    
           result = {"result": json.loads(response.read())}
    
           return (True, result, response.getcode())
    
        except (HTTPError, httplib.HTTPException) as http_exception:
    
            module.fail_json(
                msg=("Error while performing update_account."
                     "Please validate parameters provided."
                     "\n*** end_point=%s%s\n ==> %s" % (api_base_url, end_point, to_text(http_exception))),
                payload=payload,
                headers=headers,
                status_code=http_exception.code)
    
        except Exception as unknown_exception:
    
            module.fail_json(
                msg=("Unknown error while performing update_account."
                     "\n*** end_point=%s%s\n%s" % (api_base_url, end_point, to_text(unknown_exception))),
                payload=payload,
                headers=headers,
                status_code=-1)



def add_account(module):

    logging.debug("Adding Account")

    cyberark_session = module.params["cyberark_session"]
    api_base_url = cyberark_session["api_base_url"]
    validate_certs = cyberark_session["validate_certs"]

    # Prepare result, end_point, and headers
    result = {}
    HTTPMethod = "POST"
    end_point = "/PasswordVault/api/Accounts"

    headers = {'Content-Type': 'application/json',
               "Authorization": cyberark_session["token"]}

    payload = {"safeName": module.params["safe"]}

    for parameter_name in module.params.keys():
        if parameter_name not in ansible_specific_parameters and module.params[parameter_name] is not None:

            if parameter_name not in cyberark_reference_fieldnames:
                module_parm_value = deep_get(module.params, parameter_name, _empty, False)
                if module_parm_value != removal_value:
                    payload[parameter_name] = module_parm_value # module.params[parameter_name]
            else:
                module_parm_value = deep_get(module.params, parameter_name, _empty, True)
                if module_parm_value != removal_value:
                    payload[cyberark_reference_fieldnames[parameter_name]] = module_parm_value # module.params[parameter_name]        

            logging.debug("parameter_name =%s" % (parameter_name))

    logging.debug("Payload => %s" % json.dumps(payload))

    try:

       response = open_url(
           api_base_url + end_point,
           method=HTTPMethod,
           headers=headers,
           data=json.dumps(payload),
           validate_certs=validate_certs)

       result = {"result": json.loads(response.read())}

       return (True, result, response.getcode())

    except (HTTPError, httplib.HTTPException) as http_exception:

        module.fail_json(
            msg=("Error while performing add_account."
                 "Please validate parameters provided."
                 "\n*** end_point=%s%s\n ==> %s" % (api_base_url, end_point, to_text(http_exception))),
            payload=payload,
            headers=headers,
            status_code=http_exception.code)

    except Exception as unknown_exception:

        module.fail_json(
            msg=("Unknown error while performing add_account."
                 "\n*** end_point=%s%s\n%s" % (api_base_url, end_point, to_text(unknown_exception))),
            payload=payload,
            headers=headers,
            exception=traceback.format_exc(),
            status_code=-1)

def delete_account(module, existing_account):

    logging.debug("Deleting Account")

    cyberark_session = module.params["cyberark_session"]
    api_base_url = cyberark_session["api_base_url"]
    validate_certs = cyberark_session["validate_certs"]

    # Prepare result, end_point, and headers
    result = {}
    HTTPMethod = "DELETE"
    end_point = "/PasswordVault/api/Accounts/%s" % existing_account["id"]

    headers = {'Content-Type': 'application/json',
               "Authorization": cyberark_session["token"]}

    try:

       response = open_url(
           api_base_url + end_point,
           method=HTTPMethod,
           headers=headers,
           validate_certs=validate_certs)

       result = {"result": None}

       return (True, result, response.getcode())

    except (HTTPError, httplib.HTTPException) as http_exception:

        module.fail_json(
            msg=("Error while performing delete_account."
                 "Please validate parameters provided."
                 "\n*** end_point=%s%s\n ==> %s" % (api_base_url, end_point, to_text(http_exception))),
            headers=headers,
            status_code=http_exception.code)

    except Exception as unknown_exception:

        module.fail_json(
            msg=("Unknown error while performing delete_account."
                 "\n*** end_point=%s%s\n%s" % (api_base_url, end_point, to_text(unknown_exception))),
            headers=headers,
            status_code=-1)

def deep_get(dct, dotted_path, default=_empty, use_reference_table=True):
  result_dct = {}
  for key in dotted_path.split('.'):
    try:
        key_field = key
        if use_reference_table:
            key_field = cyberark_reference_fieldnames[key] if key in cyberark_reference_fieldnames else key
        logging.debug("key_field => %s" % key_field)
        
        if isinstance(dct[key_field if key_field in dct.keys() else key], dict):
            for dict_key in dct[key].keys():
                internal_key_field = dict_key
                if use_reference_table:
                    logging.debug("Getting keyname from reference table")
                    internal_key_field = cyberark_reference_fieldnames[dict_key] if dict_key in cyberark_reference_fieldnames else dict_key
                logging.debug("Internal key_field => %s" % internal_key_field)
                result_dct[internal_key_field] = deep_get(dct[key], dict_key, default, True)
        else:
            result_dct = dct[key_field if key_field in dct.keys() else key]

    except KeyError:
      if default is _empty:
        raise
      return default
  return result_dct

def get_account(module):

    logging.debug("Finding Account")

    identified_by_fields = module.params["identified_by"].split(",")
    logging.debug("Identified_by: " + json.dumps(identified_by_fields))
    safe_filter = urllib.quote("safeName eq ") + urllib.quote(module.params["safe"]) if "safe" in module.params and module.params["safe"] is not None else None
    search_string = None
    for field in identified_by_fields:
      if field not in ansible_specific_parameters:
        search_string = "%s%s" % (search_string + " " if search_string is not None else "", deep_get(module.params, field, "NOT FOUND", False))
    
    logging.debug("Search_String => %s" % search_string)
    logging.debug("Safe Filter => %s" % safe_filter)
    
    safe = module.params["safe"]
    cyberark_session = module.params["cyberark_session"]
    api_base_url = cyberark_session["api_base_url"]
    validate_certs = cyberark_session["validate_certs"]
    state = module.params["state"]
    
    end_point = None
    if search_string is not None and safe_filter is not None:
        end_point = "/PasswordVault/api/accounts?filter=%s&search=%s" % (safe_filter, urllib.quote(search_string.lstrip()))
    elif search_string is not None:
        end_point = "/PasswordVault/api/accounts?search=%s" % (search_string.lstrip())
    else:
        end_point = "/PasswordVault/api/accounts?filter=%s" % (safe_filter)
    
    logging.debug("End Point => " + end_point)

    headers = {'Content-Type': 'application/json'}
    headers["Authorization"] = cyberark_session["token"]

    try:

        logging.debug("Executing: " + api_base_url + end_point)
        response = open_url(
            api_base_url + end_point,
            method="GET",
            headers=headers,
            validate_certs=validate_certs)
        
        result_string = response.read()
        accounts_data = json.loads(result_string)
        result = {"result": accounts_data}
        
        logging.debug("RESULT => " + json.dumps(accounts_data))
        
        if accounts_data["count"] == 0:
            return (False, None, response.getcode())
        else:
            how_many = 0
            first_record_found = None
            for account_record in accounts_data["value"]:
                logging.debug("Account Record => " + json.dumps(account_record))
                found = False
                for field in identified_by_fields:
#                     record_field_name = cyberark_reference_fieldnames[field] if field in cyberark_reference_fieldnames else field
                    record_field_value = deep_get(account_record, field, "NOT FOUND")
                    logging.debug("Comparing field %s  | record_field_name=%s  record_field_value=%s   module.params_value=%s" %(field, field, record_field_value, deep_get(module.params, field, "NOT FOUND")))
                    if record_field_value != "NOT FOUND" and record_field_value == deep_get(module.params, field, "NOT FOUND", False):
                        found = True
                    else:
                        found = False
                        break
                if found:
                    how_many = how_many + 1
                    if first_record_found is None:
                        first_record_found = account_record 

            logging.debug("How Many: %d  First Record Found => %s" % (how_many, json.dumps(first_record_found)))
            if how_many > 1: # too many records found
                module.fail_json(
                    msg="Error while performing get_account. Too many rows (%d) found matching your criteria!" % how_many)
            else:
                return(how_many == 1, first_record_found, response.getcode())
            
    except (HTTPError, httplib.HTTPException) as http_exception:

        if http_exception.code == 404:
            return (False, None, http_exception.code)
        else:
            module.fail_json(
                msg=("Error while performing get_account."
                     "Please validate parameters provided."
                     "\n*** end_point=%s%s\n ==> %s" % (api_base_url, end_point, to_text(http_exception))),
                headers=headers,
                status_code=http_exception.code)

    except Exception as unknown_exception:

        module.fail_json(
            msg=("Unknown error while performing get_account."
                 "\n*** end_point=%s%s\n%s" % (api_base_url, end_point, to_text(unknown_exception))),
            headers=headers,
            status_code=-1)


def main():

    fields = {
        "state": {"type": "str",
                  "choices": ["present", "absent"],
                  "default": "present"},
        "logging_level": {"type": "str",
                  "choices": ["NOTSET", "DEBUG", "INFO"]},
        "logging_file": {"type": "str", "default": "/tmp/ansible_cyberark.log"},
        "api_base_url": {"type": "str"},
        "validate_certs": {"type": "bool",
                           "default": "true"},
        "cyberark_session": {"required": True, "type": "dict"},
        "identified_by": {"required": False, "type": "str", "default": "username,address,platform_id"},
        "safe": {"required": True, "type": "str"},
        "platform_id": {"required": False, "type": "str"},
        "address": {"required": False, "type": "str"},
        "name": {"required": False, "type": "str"},
        "secret_type": {
                        "required": False, 
                        "type": "str",
                        "choices": ["password", "key"],
                        "default": "password"
                       },
        "secret": {"required": False, "type": "str"},
        "username": {"required": False, "type": "str"},
        "secret_management": {"required": False, "type": "dict", "options": {"automatic_management_enabled": {"type": "bool"}, "manual_management_reason": {"type": "str"}}},
        "remote_machines_access": {"required": False, "type": "dict", "options": {"remote_machines": {"type": "str"}, "access_restricted_to_remote_machines": {"type": "bool"}}},
        "platform_account_properties": {"required": False, "type": "dict"},
    }
    
    module = AnsibleModule(
        argument_spec=fields,
        supports_check_mode=True)

    if module.params["logging_level"] is not None:
        logging.basicConfig(filename=module.params["logging_file"], level=module.params["logging_level"])
    
    logging.info("Starting Module")

    state = module.params["state"]

    (found, account_record, status_code) = get_account(module)
    logging.debug("Account was %s, status_code=%s" %("FOUND" if found else "NOT FOUND", status_code))
    
    changed = False
    result = {"result": account_record}
    
    if (state == "present"):
    
        if found: # Account already exists, let's verify if we need to update it
            (changed, result, status_code) = update_account(module, account_record)
        else: # Account does not exist, and we need to create it
            (changed, result, status_code) = add_account(module)
    
    elif (found and state == "absent"):
        (changed, result, status_code) = delete_account(module, account_record)


    module.exit_json(
        changed=changed,
        cyberark_account=result,
        status_code=status_code)


if __name__ == '__main__':
    main()
