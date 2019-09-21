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
module: cyberark_credential
short_description: Module for retrieval of CyberArk vaulted credential using PAS Web Services SDK through the Central Credential Provider 
author: Edward Nunez @ CyberArk BizDev (@enunez-cyberark, @cyberark-bizdev, @erasmix @JimmyJamCABD)
version_added: 2.4
description:
    - Creates a URI for retrieving a credential from a password object stored in the Cyberark Vault.  The request uses the Privileged 
      Account Security Web Services SDK through the Central Credential Provider by requesting access with an Application ID.


options:
    api_base_url:
        type: string
        required: 'Yes'
        description:
            - A string containing the base URL of the server hosting the Central Credential Provider
    validate_certs:
        type: bool
        required: 'No'
        default: 'No'
        description:
            - If C(false), SSL certificate chain will not be validated.  This should only
              set to C(true) if you have a root CA certificate installed on each node.
    app_id:
        type: string
        required: 'Yes'
        description:
            - A string containing the Application ID authorized for retrieving the credential
    query:
        type: string
        required: 'Yes'
        description:
            - A string containing details of the object being queried
        parameters:
            Safe=<safe name>
            Folder=<folder name within safe>
            Object=<object name>
            UserName=<username of object>
            Address=<address listed for object>
            Database=<optional file category for database objects>
            PolicyID=<platform id managing object>
    connection_timeout:
        type: integer
        required: 'No'
        default: '30'
        description:
            - An integer value of the allowed time before the request returns failed
    query_format:
        type: choice
        required: 'No'
        default: 'Exact'
        description:
            - The format for which your Query will be received by the CCP
        parameters:
            Exact
            Regexp
    fail_request_on_password_change:
        type: bool
        required: 'No'
        default: 'False'
        description:
            - A boolean parameter for completing the request in the middle of a password change of the requested credential
    client_cert:
        type: string
        required: 'No'
        description:
            - A string containing the file location and name of the client certificate used for authentication
    client_key:
        type: string
        required: 'No'
        description:
            - A string containing the file location and name of the private key of the client certificate used for authentication
    reason:
        type: string
        required: 'Only if the Policy managing the object requires it'
        description:
            - Reason for requesting credential if required by policy
'''

EXAMPLES = '''
- name: credential retrieval basic
  cyberark_credential:
    api_base_url: "http://10.10.0.1"
    app_id: "TestID"
    query: "Safe=test;UserName=admin"
  register: {{ result }}

  result:
     { api_base_url }"/AIMWebService/api/Accounts?AppId="{ app_id }"&Query="{ query }


- name: credential retrieval advanced
  cyberark_credential:
    api_base_url: "https://components.cyberark.local"
    validate_certs: yes
    client_cert: /etc/pki/ca-trust/source/client.pem
    client_key: /etc/pki/ca-trust/source/priv-key.pem
    app_id: "TestID"
    query: "Safe=test;UserName=admin"
    connection_timeout: 60
    query_format: Exact
    fail_request_on_password_change: True
    reason: "requesting credential for Ansible deployment"
  register: {{ result }}

  result:
     { api_base_url }"/AIMWebService/api/Accounts?AppId="{ app_id }"&Query="{ query }"&ConnectionTimeout="{ connection_timeout }"&QueryFormat="{ query_format }"&FailRequestOnPasswordChange="{ fail_request_on_password_change }
'''

RETURN = '''
"{{}}": {
    "changed": false,
    "failed": false,
    "result": {
        "Address": "string"
            description: The target address of the credential being queried 
            type: string
            returned: if required
        "Content": "string"
            description: The password for the object being queried
            type: string
            returned: always
        "CreationMethod": "string"
            description: This is how the object was created in the Vault
            type: string
            returned: always
        "DeviceType": "string"
            description: An internal File Category for more granular management of Platforms
            type: string
            returned: always
        "Folder": "string"
            description: The folder within the Safe where the credential is stored 
            type: string
            returned: always
        "Name": "string"
            description: The Cyberark unique object ID of the credential being queried 
            type: string
            returned: always
        "PasswordChangeInProcess": "bool"
            description: If the password has a change flag placed by the CPM 
            type: bool
            returned: always
        "PolicyID": "string"
            description: Whether or not SSL certificates should be validated.
            type: string
            returned: if assigned to a policy
        "Safe": "string"
            description: The safe where the queried credential is stored 
            type: string
            returned: always
        "Username": "string"
            description: The username of the credential being queried 
            type: string
            returned: if required
        "LogonDomain": "string"
            description: The Address friendly name resolved by the CPM 
            type: string
            returned: if populated
        "CPMDisabled": "string"
            description: A description of why this vaulted credential is not being managed by the CPM
            type: string
            returned: if CPM management is disabled and a reason is given
        },
        "status_code": 200
    }
}
'''

from ansible.module_utils._text import to_text
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module.utils.six.moves.urllib.parse import quote
import json
import urllib
try:
    import httplib
except ImportError:
    # Python 3
    import http.client as httplib


def retrieve_credential(module):

    # Getting parameters from module

    api_base_url = module.params["api_base_url"]
    validate_certs = module.params["validate_certs"]
    app_id = module.params["app_id"]
    query = module.params["query"]
    connection_timeout = module.params["connection_timeout"]
    query_format = module.params["query_format"]
    fail_request_on_password_change = module.params["fail_request_on_password_change"]
    client_cert = None
    client_key = None

    if "client_cert" in module.params:
        client_cert = module.params["client_cert"]
    if "client_key" in module.params:
        client_key = module.params["client_key"]

    end_point = ("/AIMWebService/api/Accounts?AppId=%s&Query=%s&ConnectionTimeout=%s&QueryFormat=%s"
                 "&FailRequestOnPasswordChange=%s") % (quote(app_id), quote(query),
                                                       connection_timeout, query_format,
                                                       fail_request_on_password_change)

    if "reason" in module.params and module.params["reason"] != None:
        reason = quote(module.params["reason"])
        end_point = end_point + "&reason=%s" % reason

    result = None
    response = None

    try:

        response = open_url(
            api_base_url + end_point,
            method="GET",
            validate_certs=validate_certs,
            client_cert=client_cert,
            client_key=client_key)

    except (HTTPError, httplib.HTTPException) as http_exception:

        module.fail_json(
            msg=("Error while retrieving credential."
                 "Please validate parameters provided, and permissions for "
                 "the application and provider in CyberArk."
                 "\n*** end_point=%s%s\n ==> %s" % (api_base_url, end_point,
                                                    to_text(http_exception))),
            status_code=http_exception.code)

    except Exception as unknown_exception:

        module.fail_json(
            msg=("Unknown error while retrieving credential."
                 "\n*** end_point=%s%s\n%s" % (api_base_url, end_point,
                                               to_text(unknown_exception))),
            status_code=-1)

    if response.getcode() == 200:  # Success

        # Result token from REST Api uses a different key based
        try:
            result = json.loads(response.read())
        except Exception as exc:
            module.fail_json(
                msg="Error obtain cyberark credential result from http body\n%s" % (to_text(exc)),
                status_code=-1)

        return (result, response.getcode())

    else:
        module.fail_json(
            msg="error in end_point=>" +
            end_point)

def main():

    fields = {
        "api_base_url": {"required": True, "type": "str"},
        "app_id": {"required": True, "type": "str"},
        "query": {"required": True, "type": "str"},
        "reason": {"required": False, "type": "str"},
        "connection_timeout": {"required": False, "type": "int", "default": 30},
        "query_format": {"required": False, "type": "str", "choices": ["Exact", "Regexp"],
                         "default": "Exact"},
        "fail_request_on_password_change": {"required": False, "type": "bool", "default": False},
        "validate_certs": {"type": "bool",
                           "default": True},
        "client_cert": {"type": "str", "required": False},
        "client_key": {"type": "str", "required": False},
        "state": {"type": "str",
                  "choices": ["present"],
                  "default": "present"},
    }

    module = AnsibleModule(
        argument_spec=fields,
        supports_check_mode=True)

    (result, status_code) = retrieve_credential(module)

    module.exit_json(
        changed=False,
        result=result,
        status_code=status_code)


if __name__ == '__main__':
    main()
