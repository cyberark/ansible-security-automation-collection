# cyberark_user

This module allows admins to Add, Delete, and Modify CyberArk Vault Users.  The ability to modify consists of the following:

* Enable User<br>
* Disable User<br>
* Add/Remove Group<br>
* Set New Password<br>
* Force "change password at next login"<br>
* Modify User Information Fields<br>
  * Email<br>
  * First Name<br>
  * Last Name<br>
  * Expiry Date<br>
  * User Type<br>
  * Location<br>

#### Limitations
**Idempotency** - All actions taken in the playbook adhere to the Ansible idempotency guidelines _except_ for password change.  If you have the playbook set to modify a password it will "modify" the password every time the playbook is run, even if it is the same password.<br>
**Group Creation** - If the value for `group_name` does not exist in the Vault it will not create that group, the user action that was expected will fail.

#### Available Fields
    
```
options:
    username:
        description:
            - The name of the user who will be queried (for details), added, updated or deleted.
        type: str
        required: true
    state:
        description:
            - Specifies the state needed for the user present for create user, absent for delete user.
        type: str
        choices: [ absent, present ]
        default: present
    cyberark_session:
        description:
            - Dictionary set by a CyberArk authentication containing the different values to perform actions on a logged-on CyberArk session,
              please see M(cyberark_authentication) module for an example of cyberark_session.
        type: dict
        required: true
    initial_password:
        description:
            - The password that the new user will use to log on the first time.
            - This password must meet the password policy requirements.
            - This parameter is required when state is present -- Add User.
        type: str
    new_password:
        description:
            - The user updated password. Make sure that this password meets the password policy requirements.
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
            - Whether or not the user must change their password in their next logon.
        type: bool
        default: false
    expiry_date:
        description:
            - The date and time when the user account will expire and become disabled.
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
        default: false
    location:
        description:
            - The Vault Location for the user.
        type: str
    group_name:
        description:
            - The name of the group the user will be added to.
        type: str
```
## Example Playbooks

This playbook will check if username `admin` exists, if it does not, it will provision the user in the Vault, add it to the `Auditors` group and set the account to be changed at first logon.

```yaml
- name: Logon to CyberArk Vault using PAS Web Services SDK
  cyberark_authentication:
    api_base_url: https://components.cyberark.local
    use_shared_logon_authentication: true

- name: Create user, add to Group
  cyberark_user:
    username: admin
    first_name: "Cyber"
    last_name: "Admin"
    email: "cyber.admin@ansibledev.com"
    initial_password: PA$$Word123
    user_type_name: EPVUser
    change_password_on_the_next_logon: true
    group_name: Auditors
    state: present
    cyberark_session: '{{ cyberark_session }}'
  register: cyberarkaction

- name: Logoff from CyberArk Vault
  cyberark_authentication:
    state: absent
    cyberark_session: '{{ cyberark_session }}'
```

This playbook will identify the user and delete it from the CyberArk Vault based on the `state: absent` parameter.

```yaml
- name: Logon to CyberArk Vault using PAS Web Services SDK - use_shared_logon_authentication
  cyberark_authentication:
    api_base_url: "{{ web_services_base_url }}"
    use_shared_logon_authentication: true

- name: Removing a CyberArk User
  cyberark_user:
    username: "ansibleuser"
    state: absent
    cyberark_session: "{{ cyberark_session }}"
  register: cyberarkaction
    
- name: Logoff from CyberArk Vault
  cyberark_authentication:
    state: absent
    cyberark_session: "{{ cyberark_session }}"
```
This playbook is an example of disabling a user based on the `disabled: true` value with that authentication using the credential set in Tower.
```yaml
- name: Logon to CyberArk Vault using PAS Web Services SDK - Not use_shared_logon_authentication
  cyberark_authentication:
    api_base_url: "{{ web_services_base_url }}"
    username: "{{ password_object.password }}"
    password: "{{ password_object.passprops.username }}"
    use_shared_logon_authentication: false
    
- name: Disabling a CyberArk User
  cyberark_user:
    username: "ansibleuser"
    disabled: true
    cyberark_session: "{{ cyberark_session }}"
  register: cyberarkaction

- name: Logoff from CyberArk Vault
  cyberark_authentication:
    state: absent
    cyberark_session: "{{ cyberark_session }}"
```
