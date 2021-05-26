#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Ansible Project
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "certified",
}

DOCUMENTATION = r"""
---
module: cyberark_user
short_description: CyberArk User Management using PAS Web Services SDK.
author:
  - Edward Nunez (@enunez-cyberark)
  - Cyberark Bizdev (@cyberark-bizdev)
  - Erasmo Acosta (@erasmix)
  - James Stutes (@jimmyjamcabd)
version_added: 2.4
description:
    - CyberArk User Management using PAS Web Services SDK,
      It currently supports the following actions Get User Details, Add User,
      Update User, Delete User.

options:
    username:
        description:
            - The name of the user who will be queried (for details), added,
              updated or deleted.
            - For deletion, vault_user_id will be prefered.
        type: str
        required: True
    state:
        description:
            - Specifies the state needed for the user present for create user,
              absent for delete user.
        type: str
        choices: [ absent, present ]
        default: present
    logging_level:
        description:
            - Parameter used to define the level of troubleshooting output to
              the C(logging_file) value.
        required: true
        choices: [NOTSET, DEBUG, INFO]
        default: NOTSET
        type: str
    logging_file:
        description:
            - Setting the log file name and location for troubleshooting logs.
        required: false
        default: /tmp/ansible_cyberark.log
        type: str
    cyberark_session:
        description:
            - Dictionary set by a CyberArk authentication containing the
              different values to perform actions on a logged-on CyberArk
              session, please see M(cyberark_authentication) module for an
              example of cyberark_session.
        type: dict
        required: True
    initial_password:
        description:
            - The password that the new user will use to log on the first time.
            - This password must meet the password policy requirements.
            - This parameter is required when state is present -- Add User.
        type: str
    new_password:
        description:
            - The user updated password. Make sure that this password meets
              the password policy requirements.
        type: str
    email:
        description:
            - The user email address.
        type: str
    first_name:
        description:
            - The user first name.
        type: str
    last_name:
        description:
            - The user last name.
        type: str
    change_password_on_the_next_logon:
        description:
            - Whether or not the user must change their password in their
              next logon.
        type: bool
        default: no
    expiry_date:
        description:
            - The date and time when the user account will expire and become
              disabled.
        type: str
    user_type_name:
        description:
            - The type of user.
            - The parameter defaults to C(EPVUser).
        type: str
    disabled:
        description:
            - Whether or not the user will be disabled.
        type: bool
        default: no
    location:
        description:
            - The Vault Location for the user.
        type: str
    group_name:
        description:
            - The name of the group the user will be added to.
            - Causes an additional lookup in cyberark
            - Will be ignored if vault_id is used
            - Will cause a failure if group is missing or more than one group with that name exists
        type: str
    timeout:
        description:
            - How long to wait for the server to send data before giving up
        type: float
        default: 10
    vault_id:
        description:
            - The ID of the user group to add the user to
            - Prefered over group_name
        type: int
    vault_user_id:
        description:
            - The ID of the user to delete
            - Prefered over username
        type: int
    authorization:
        description:
            - A list of authorization options for this user.
            - Options can include AddSafe and AuditUsers
            - The default provides backwards compatability with older versions of the collection
        type: list
        default:
          - AddSafe
          - AuditUsers
"""

EXAMPLES = r"""
- name: Logon to CyberArk Vault using PAS Web Services SDK
  cyberark_authentication:
    api_base_url: https://components.cyberark.local
    use_shared_logon_authentication: yes

- name: Create user & immediately add it to a group
  cyberark_user:
    username: username
    initial_password: password
    user_type_name: EPVUser
    change_password_on_the_next_logon: no
    group_name: GroupOfUser
    state: present
    cyberark_session: '{{ cyberark_session }}'

- name: Make sure user is present and reset user credential if present
  cyberark_user:
    username: Username
    new_password: password
    disabled: no
    state: present
    cyberark_session: '{{ cyberark_session }}'

- name: Logoff from CyberArk Vault
  cyberark_authentication:
    state: absent
    cyberark_session: '{{ cyberark_session }}'
"""

RETURN = r"""
changed:
    description: Whether there was a change done.
    type: bool
    returned: always
cyberark_user:
    description: Dictionary containing result properties.
    returned: always
    type: complex
    contains:
        result:
            description: user properties when state is present
            type: dict
            returned: success
status_code:
    description: Result HTTP Status code
    returned: success
    type: int
    sample: 200
"""

import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text
from ansible.module_utils.six.moves import http_client as httplib
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module_utils.urls import open_url
from ansible.module_utils.six.moves.urllib.parse import quote
import logging


def construct_url(api_base_url, end_point):
    return "{}/{}".format(api_base_url.rstrip("/"), end_point.lstrip("/"))

def user_details(module):

    # Get username from module parameters, and api base url
    # along with validate_certs from the cyberark_session established
    username = module.params["username"]
    cyberark_session = module.params["cyberark_session"]
    api_base_url = cyberark_session["api_base_url"]
    validate_certs = cyberark_session["validate_certs"]

    # Prepare result, end_point, and headers
    result = {}
    end_point = "/PasswordVault/WebServices/PIMServices.svc/Users/{0}".format(username)
    url = construct_url(api_base_url, end_point)

    headers = {"Content-Type": "application/json"}
    headers["Authorization"] = cyberark_session["token"]

    try:

        response = open_url(
            url,
            method="GET",
            headers=headers,
            validate_certs=validate_certs,
            timeout=module.params['timeout'],
        )
        result = {"result": json.loads(response.read())}

        return (False, result, response.getcode())

    except (HTTPError, httplib.HTTPException) as http_exception:

        if http_exception.code == 404:
            return (False, None, http_exception.code)
        else:
            module.fail_json(
                msg=(
                    "Error while performing user_details."
                    "Please validate parameters provided."
                    "\n*** end_point=%s\n ==> %s"
                    % (url, to_text(http_exception))
                ),
                headers=headers,
                status_code=http_exception.code,
            )

    except Exception as unknown_exception:

        module.fail_json(
            msg=(
                "Unknown error while performing user_details."
                "\n*** end_point=%s\n%s"
                % (url, to_text(unknown_exception))
            ),
            headers=headers,
            status_code=-1,
        )


def user_add_or_update(module, HTTPMethod, existing_info):

    # Get username from module parameters, and api base url
    # along with validate_certs from the cyberark_session established
    username = module.params["username"]
    cyberark_session = module.params["cyberark_session"]
    api_base_url = cyberark_session["api_base_url"]
    validate_certs = cyberark_session["validate_certs"]

    # Prepare result, paylod, and headers
    result = {}
    payload = {}
    headers = {
        "Content-Type": "application/json",
        "Authorization": cyberark_session["token"],
    }

    # end_point and payload sets different depending on POST/PUT
    # for POST -- create -- payload contains username
    # for PUT -- update -- username is part of the endpoint
    if HTTPMethod == "POST":
        end_point = "PasswordVault/api/Users"
        payload["UserName"] = username
        if (
            "initial_password" in list(module.params.keys())
            and module.params["initial_password"] is not None
        ):
            payload["InitialPassword"] = module.params["initial_password"]

    elif HTTPMethod == "PUT":
        end_point = "/PasswordVault/WebServices/PIMServices.svc/Users/{0}"
        end_point = end_point.format(username)

    # --- Optionally populate payload based on parameters passed ---
    if "new_password" in module.params and module.params["new_password"] is not None:
        payload["NewPassword"] = module.params["new_password"]

    if "email" in module.params and module.params["email"] is not None:
        payload["Email"] = module.params["email"]

    if "first_name" in module.params and module.params["first_name"] is not None:
        payload["FirstName"] = module.params["first_name"]

    if "last_name" in module.params and module.params["last_name"] is not None:
        payload["LastName"] = module.params["last_name"]

    if (
        "change_password_on_the_next_logon" in module.params
        and module.params["change_password_on_the_next_logon"] is not None
    ):
        payload["ChangePasswordOnTheNextLogon"] = module.params[
            "change_password_on_the_next_logon"
        ]

    if "expiry_date" in module.params and module.params["expiry_date"] is not None:
        payload["ExpiryDate"] = module.params["expiry_date"]

    if (
        "user_type_name" in module.params
        and module.params["user_type_name"] is not None
    ):
        payload["UserTypeName"] = module.params["user_type_name"]
        # In API V2 the parameter is called userType, V2 ignores the UserTypeName
        payload["userType"] = module.params["user_type_name"]

    if "disabled" in module.params and module.params["disabled"] is not None:
        payload["Disabled"] = module.params["disabled"]

    if "location" in module.params and module.params["location"] is not None:
        payload["Location"] = module.params["location"]

    if module.params.get("authorization", None) is not None:
        payload["VaultAuthorization"] = module.params["authorization"]

    # --------------------------------------------------------------
    logging.debug(
        "HTTPMethod = " + HTTPMethod + " module.params = " + json.dumps(module.params)
    )
    logging.debug("Existing Info: %s", json.dumps(existing_info))
    logging.debug("payload => %s", json.dumps(payload))

    if HTTPMethod == "PUT" and (
        "new_password" not in module.params or module.params["new_password"] is None
    ):
        logging.info("Verifying if needs to be updated")
        proceed = False
        updateable_fields = [
            "Email",
            "FirstName",
            "LastName",
            "ChangePasswordOnTheNextLogon",
            "ExpiryDate",
            "UserTypeName",
            "Disabled",
            "Location",
        ]
        for field_name in updateable_fields:
            logging.debug("#### field_name : %s", field_name)
            if (
                field_name in payload
                and field_name in existing_info
                and payload[field_name] != existing_info[field_name]
            ):
                logging.debug("Changing value for %s", field_name)
                proceed = True
    else:
        proceed = True

    if proceed:
        logging.info("Proceeding to either update or create")
        url = construct_url(api_base_url, end_point)
        try:

            # execute REST action
            response = open_url(
                url,
                method=HTTPMethod,
                headers=headers,
                data=json.dumps(payload),
                validate_certs=validate_certs,
                timeout=module.params['timeout'],
            )

            result = {"result": json.loads(response.read())}

            return (True, result, response.getcode())

        except (HTTPError, httplib.HTTPException) as http_exception:

            module.fail_json(
                msg=(
                    "Error while performing user_add_or_update."
                    "Please validate parameters provided."
                    "\n*** end_point=%s\n ==> %s"
                    % (url, to_text(http_exception))
                ),
                payload=payload,
                headers=headers,
                status_code=http_exception.code,
            )
        except Exception as unknown_exception:

            module.fail_json(
                msg=(
                    "Unknown error while performing user_add_or_update."
                    "\n*** end_point=%s\n%s"
                    % (url, to_text(unknown_exception))
                ),
                payload=payload,
                headers=headers,
                status_code=-1,
            )
    else:
        return (False, existing_info, 200)


def resolve_username_to_id(module):
    username = module.params["username"]
    cyberark_session = module.params["cyberark_session"]
    api_base_url = cyberark_session["api_base_url"]
    validate_certs = cyberark_session["validate_certs"]
    result = {}
    url = construct_url(api_base_url, "PasswordVault/api/Users?search={}".format(username))
    headers = {
      "Content-Type": "application/json",
      "Authorization": cyberark_session["token"],
    }
    try:
        response = open_url(
            url,
            method="GET",
            headers=headers,
            validate_certs=validate_certs,
	    timeout=module.params['timeout'],
        )
        users = json.loads(response.read())
        if users['Total'] == 0:
            # The user does not exist
            return None
        elif users['Total'] == 1:
            return users['Users'][0]['id']
        else:
            module.fail_json("Found more than one user matching %s. Use vault_user_id instead" % (username))

    except (HTTPError, httplib.HTTPException) as http_exception:
        exception_text = to_text(http_exception)
        module.fail_json(msg=(
                "Error while performing user_search."
                "Please validate parameters provided."
                "\n*** end_point=%s\n ==> %s"
                % (url, exception_text)
            ),
            headers=headers,
            status_code=http_exception.code,
        )
    except Exception as unknown_exception:
        module.fail_json(msg=(
                "Unknown error while performing user search."
                "\n*** end_point=%s\n%s"
                % (url, to_text(unknown_exception))
            ),
            headers=headers,
            status_code=-1,
        )

def user_delete(module):

    # Get username from module parameters, and api base url
    # along with validate_certs from the cyberark_session established
    username = module.params["username"]
    cyberark_session = module.params["cyberark_session"]
    api_base_url = cyberark_session["api_base_url"]
    validate_certs = cyberark_session["validate_certs"]
    vault_user_id = module.params["vault_user_id"]

    # Prepare result, end_point, and headers
    result = {}
    if not vault_user_id and username:
        vault_user_id = resolve_username_to_id(module)
        # If the user was not found by username we can return unchanged
        if vault_user_id == None:
          return (False, result, None)

    end_point = ("PasswordVault/api/Users/{0}").format(vault_user_id)

    headers = {"Content-Type": "application/json"}
    headers["Authorization"] = cyberark_session["token"]
    url = construct_url(api_base_url, end_point)

    try:

        # execute REST action
        response = open_url(
            url,
            method="DELETE",
            headers=headers,
            validate_certs=validate_certs,
	    timeout=module.params['timeout'],
        )

        result = {"result": {}}

        return (True, result, response.getcode())

    except (HTTPError, httplib.HTTPException) as http_exception:

        exception_text = to_text(http_exception)
        if http_exception.code == 404 and "ITATS003E" in exception_text:
            # User does not exist
            result = {"result": {}}
            return (False, result, http_exception.code)
        else:
            module.fail_json(
                msg=(
                    "Error while performing user_delete."
                    "Please validate parameters provided."
                    "\n*** end_point=%s\n ==> %s"
                    % (url, exception_text)
                ),
                headers=headers,
                status_code=http_exception.code,
            )

    except Exception as unknown_exception:

        module.fail_json(
            msg=(
                "Unknown error while performing user_delete."
                "\n*** end_point=%s\n%s"
                % (url, to_text(unknown_exception))
            ),
            headers=headers,
            status_code=-1,
        )


def resolve_group_name_to_id(module):
    group_name = module.params["group_name"]
    cyberark_session = module.params["cyberark_session"]
    api_base_url = cyberark_session["api_base_url"]
    validate_certs = cyberark_session["validate_certs"]
    headers = {
      "Content-Type": "application/json",
      "Authorization": cyberark_session["token"]
    }
    url = construct_url(api_base_url, "/PasswordVault/api/UserGroups?search={}".format(quote(group_name)))
    try:
        response = open_url(
            url,
            method="GET",
            headers=headers,
            validate_certs=validate_certs,
            timeout=module.params['timeout'],
        )
        groups = json.loads(response.read())
        if groups['count'] == 0:
            module.fail_json(msg=("Unable to find a group named %s" % (group_name)))
        if groups['count'] > 1:
            module.fail_json(msg=("Found more than one group named %s, please use vault_id parameter instead" % (group_name)))
        return groups['value'][0]['id']

    except (HTTPError, httplib.HTTPException) as http_exception:
        module.fail_json(msg=(
            "Error while looking up group %s.\n*** end_point=%s\n ==> %s"
            % (group_name, url, to_text(http_exception))
            ),
            payload={},
            headers=headers,
            status_code=http_exception.code,
        )
    except Exception as unknown_exception:
        module.fail_json(msg=(
                "Unknown error while looking up group %s.\n*** end_point=%s\n%s"
                % (group_name, url, to_text(unknown_exception))
            ),
            payload={},
            headers=headers,
            status_code=-1,
        )


def user_add_to_group(module):

    # Get username, and groupname from module parameters, and api base url
    # along with validate_certs from the cyberark_session established

    # Not needed for new version
    username = module.params["username"]
    group_name = module.params["group_name"]
    vault_id = module.params["vault_id"]
    member_id = username
    member_type = (
        "Vault"
        if module.params["member_type"] is None
        else module.params["member_type"]
    )
    domain_name = module.params["domain_name"] if member_type == "domain" else None

    cyberark_session = module.params["cyberark_session"]
    api_base_url = cyberark_session["api_base_url"]
    validate_certs = cyberark_session["validate_certs"]

    # Prepare result, end_point, headers and payload
    result = {}
    headers = {
      "Content-Type": "application/json",
      "Authorization": cyberark_session["token"]
    }

    # If we went "old school" and were provided a group_name instead of a vault_id we need to resolve it
    if group_name and not vault_id:
        # If we were given a group_name we need to lookup the vault_id
        vault_id = resolve_group_name_to_id(module)

    end_point = ("/PasswordVault/api/UserGroups/{0}/Members").format(vault_id)

    # payload = {"UserName": username}
    payload = {"memberId": member_id, "memberType": member_type}
    if domain_name:
        payload["domain_name"] = domain_name

    url = construct_url(api_base_url, end_point)
    try:

        # execute REST action
        response = open_url(
            url,
            method="POST",
            headers=headers,
            data=json.dumps(payload),
            validate_certs=validate_certs,
	    timeout=module.params['timeout'],
        )

        result = {"result": {}}

        return (True, result, response.getcode())

    except (HTTPError, httplib.HTTPException) as http_exception:

        exception_text = to_text(http_exception)
        if http_exception.code == 409 and "ITATS262E" in exception_text:
            # User is already member of Group
            return (False, None, http_exception.code)
        else:
            module.fail_json(
                msg=(
                    "Error while performing user_add_to_group."
                    "Please validate parameters provided."
                    "\n*** end_point=%s\n ==> %s"
                    % (url, exception_text)
                ),
                payload=payload,
                headers=headers,
                status_code=http_exception.code,
            )

    except Exception as unknown_exception:

        module.fail_json(
            msg=(
                "Unknown error while performing user_add_to_group."
                "\n*** end_point=%s\n%s"
                % (url, to_text(unknown_exception))
            ),
            payload=payload,
            headers=headers,
            status_code=-1,
        )


def main():

    module = AnsibleModule(
        argument_spec=dict(
            username=dict(type="str", required=True),
            state=dict(type="str", default="present", choices=["absent", "present"]),
            logging_level=dict(
                type="str", default="NOTSET", choices=["NOTSET", "DEBUG", "INFO"]
            ),
            logging_file=dict(type="str", default="/tmp/ansible_cyberark.log"),
            cyberark_session=dict(type="dict", required=True),
            initial_password=dict(type="str", no_log=True),
            new_password=dict(type="str", no_log=True),
            email=dict(type="str"),
            first_name=dict(type="str"),
            last_name=dict(type="str"),
            change_password_on_the_next_logon=dict(type="bool"),
            expiry_date=dict(type="str"),
            user_type_name=dict(type="str"),
            disabled=dict(type="bool"),
            location=dict(type="str"),
            group_name=dict(type="str"),
            vault_id=dict(type="int"),
            vault_user_id=dict(type="int"),
            member_type=dict(type="str"),
            domain_name=dict(type="str"),
            timeout=dict(type="float", default=10),
            authorization=dict(type="list", required=False, default=[ 'AddSafe', 'AuditUsers' ]),
        )
    )

    if module.params["logging_level"] is not None:
        logging.basicConfig(
            filename=module.params["logging_file"], level=module.params["logging_level"]
        )

    logging.info("Starting Module")

    state = module.params["state"]
    group_name = module.params["group_name"]

    if state == "present":
        (changed, result, status_code) = user_details(module)

        if status_code == 200:
            # User already exists

            (changed, result, status_code) = user_add_or_update(
                module, "PUT", result["result"]
            )

        elif status_code == 404:
            # User does not exist, proceed to create it
            (changed, result, status_code) = user_add_or_update(module, "POST", None)

        # Add user to group if needed
        if group_name is not None or vault_id is not None:
          (group_change, no_result, no_status_code) = user_add_to_group(module)
          changed = changed or group_change

    elif state == "absent":
        (changed, result, status_code) = user_delete(module)

    module.exit_json(changed=changed, cyberark_user=result, status_code=status_code)


if __name__ == "__main__":
    main()
