# cyberark_account

Allows for adding, deleting, modifying a privileged credential within the Cyberark Vault.  The request uses the Privileged Account Security Web Services SDK.<br>

The ability to modify consists of the following:

* Password (see secret_management)
* Safe
* Platform
* Address
* Object Name
* Username
* Platform Account Properties
  * These are the parameters listed in the Platform under `UI & Workflows -> Properties` and are unique to each Platform (see image below)
* Remote Machines Access

![Platform Account Properties](https://github.com/cyberark/ansible-security-automation-collection/blob/master/docs/images/platform_account_properties.JPG?raw=true)

### secret_management
The `secret_management` dictionary provides the capability to set a CPM password rotation flag on an existing account.

The available options are as follows:<br>

`automatic_management_enabled`: bool<br>
`manual_management_reason`: This is a string value that populates the Reason field is you have set an account to not be managed by the CPM.  This value is only necessary if `automatic_management_enabled` is set to false.<br>
`management_action`: This value indicates what type CPM management flag will be placed on the account
* change - <br>
* change_immediately - <br>
* reconcile - <br>

`new_secret`: This parameter is available to set the value of the new password<br>
`perform_secret_management`: This parameter was allows the option to place a CPM management flag on an account upon creation of an account object.
* always - All `secret_management` actions will follow the table below at all times.
* on_create - Will place a CPM management flag according to the table below ONLY on creation of an account object.

#### Secret Management Action Table
| management_action   | new_secret  | Action  |
| :---------: | :----: | :----- |
| change | populated | change password to set value at next scheduled rotation |
| change | NULL | rotate password at next scheduled rotation |
| change_immediately | populated | change immediately to the set value |
| change_immediately | NULL | rotate immediately |
| reconcile | populated | reconcile immediately NOT to set value |
| reconcile | NULL | reconcile immediately |
| NULL | populated | set value in Vault ONLY |


### identified_by
This property allows for the module to confidently identify the account object needing to be identified.  If multiple accounts are returned from the modules initial `Get Accounts` it will use the value(s) set in the `identified_by` parameter to direct which account is selected from the list.

**EXAMPLE:**
```
-Playbook Parameters-

cyberark_account:
  identified_by: "address,username,platform_id"
  safe: "testSafe"
  address: "dev.local"
  username: "admin"
  platform_id: WinDomain

  -This is the query sent to CyberArk Web SDK:
/api/Accounts?filter=safeName eq testSafe&search= admin dev.local

**This could return multiple accounts in the testSafe**

RETURNED:
account1
  username: administrator
  address: cyberark.dev.local
  safe: testSafe
  policyID: WinDomain

account2
  username: admin
  address: dev.local
  safe: testSafe
  policyID: WinDomain
```
With the `identified_by` parameter set the `cyberark_account` module will select the account2 object becauses the values of the `address`, `username` and `platform_id` parameters are identical matches to the values of account2 properties.

#### Limitations
**Idempotency** - All actions taken in the module adhere to the Ansible idempotency guidelines _except_ for password change.  If you have the playbook set to modify a password it will send a password change request every time the playbook is run, even if you are defining the next password value and it is the same password that is set in other runs.<br>
**Remote Machines Access** - When modifying the values in the `remote_machines_access` dictionary be mindful of the `platform_id` value.  Remote Machines Access values are stored at the Vault database level and not stored as File Categories.  It is a function that is only available with the `WinDomain` platform and if you attempt to assign these values to another platform it will cause errors in the PSM functionality.


#### Available Fields
```
options:
    state:
        description:
            - Assert the desired state of the account C(present) to creat or update and account object. Set to C(absent) for deletion of an account object
        required: true
        default: present
        choices: [present, absent]
        type: str
    logging_level:
        description:
            - Parameter used to define the level of troubleshooting output to the C(logging_file) value
        required: true
        choices: [NOTSET, DEBUG, INFO]
        type: str
    logging_file:
        description:
            - Setting the log file name and location for troubleshooting logs
        required: false
        default: /tmp/ansible_cyberark.log
        type: str
    api_base_url:
        description:
            - A string containing the base URL of the server hosting CyberArk's Privileged Account Security Web Services SDK
            - Example: U(https://<IIS_Server_Ip>/PasswordVault/api/)
        required: true
        type: str
    validate_certs:
        description:
            - If C(false), SSL certificate chain will not be validated.  This should only set to C(true) if you have a root CA certificate installed on each node.
        required: false
        default: true
        type: bool
    cyberark_session:
        description:
            - Dictionary set by a CyberArk authentication containing the different values to perform actions on a logged-on CyberArk session, please see M(cyberark_authentication) module for an example of cyberark_session.
        required: true
        type: dict
    identified_by: 
        description:
            - When an API call is made to Get Accounts, often times the default parameters passed will identify more than one account. This parameter is used to confidently identify a single account when the default query can return multiple results.
        required: false
        default: username,address,platform_id
        type: str        
    safe:
        description:
            - The safe in the Vault where the privileged account is to be located
        required: true
        type: str
    platform_id:
        description:
            - The PolicyID of the Platform that is to be managing the account
        required: false
        type: str
    address:
        description:
            - The adress of the endpoint where the privileged account is located
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
    username:
        description:
            - The username associated with the account
        required: false
        type: str
    secret_management
        description:
            - Set of parameters associated with the management of the credential
        required: false
            suboptions:
                automatic_management_enabled:
                    description:
                        - Parameter that indicates whether the CPM will manage the password or not
                    default: true
                    type: bool
                manual_management_reason:
                    description:
                        - String value indicating why the CPM will NOT manage the password
                    type: str
                management_action:
                    description:
                        - CPM action flag to be placed on the account object for credential rotation
                    choices: [change, change_immediately, reconcile]
                    type: str
                new_secret:
                    description:
                        - The actual password value that will be assigned for the CPM action to be taken
                    type: str
                perform_management_action:
                    description:
                        - C(always) will perform the management action in every action
                        - C(on_create) will only perform the management action right after the account is created
                    choices: [always, on_create]
                    default: always
                    type: str
    remote_machines_access:
        description:
            - Set of parameters for defining PSM endpoint access targets
        required: false
        type: dict
            suboptions:
                remote_machines:
                    description:
                        - List of targets allowed for this account 
                    type: str
                access_restricted_to_remote_machines:
                    description:
                        - Whether or not to restrict access only to specified remote machines
                    type: bool
    platform_account_properties:
        description:
            - Object containing key-value pairs to associate with the account, as defined by the account platform. These properties are validated against the mandatory and optional properties of the specified platform's definition. Optional properties that do not exist on the account will not be returned here. Internal properties are not returned.
        required: false
        type: dict
            suboptions:
                KEY:
                    description:
                        - Freeform key value associated to the mandatory or optional property assigned to the specified Platform's definition.
                    aliases: [Port, ExtrPass1Name, database]
                    type: str
```

## Example Playbooks


```yaml
  tasks:

    - name: Logon to CyberArk Vault using PAS Web Services SDK
      cyberark.pas.cyberark_authentication:
        api_base_url: "http://components.cyberark.local"
        validate_certs: false
        username: "bizdev"
        password: "Cyberark1"

    - name: Creating an Account using the PAS WebServices SDK
      cyberark.pas.cyberark_account:
        logging_level: DEBUG
        identified_by: "address,username"
        safe: "Test"
        address: "cyberark.local"
        username: "administrator-x"
        platform_id: WinServerLocal
        secret: "@N&Ibl3!"
        platform_account_properties:
            LogonDomain: "cyberark"
            OwnerName: "ansible_user"
        secret_management:
            automatic_management_enabled: true
        state: present
        cyberark_session: "{{ cyberark_session }}"
      register: cyberarkaction
    
    - name: Rotate credential via reconcile and providing the password to be changed to
      cyberark.pas.cyberark_account:
        identified_by: "address,username"
        safe: "Domain_Admins"
        address: "prod.cyberark.local"
        username: "admin"
        platform_id: WinDomain
        platform_account_properties:
            LogonDomain: "PROD"
        secret_management:
            new_secret: "Ama123ah12@#!Xaamdjbdkl@#112"
            management_action: "reconcile"
            automatic_management_enabled: true
        state: present
        cyberark_session: "{{ cyberark_session }}"
      register: reconcileaccount
    
    - name: Update password only in VAULT
      cyberark.pas.cyberark_account:
        identified_by: "address,username"
        safe: "Domain_Admins"
        address: "prod.cyberark.local"
        username: "admin"
        platform_id: Generic
        new_secret: "Ama123ah12@#!Xaamdjbdkl@#112"
        state: present
        cyberark_session: "{{ cyberark_session }}"
      register: updateaccount

    - name: Retrieve account and password
      cyberark.pas.cyberark_account:
        identified_by: "address,username"
        safe: "Domain_Admins"
        address: "prod.cyberark.local"
        username: "admin"
        state: retrieve
        cyberark_session: "{{ cyberark_session }}"
      register: retrieveaccount

    - name: Logoff from CyberArk Vault
      cyberark.pas.cyberark_authentication:
        state: absent
        cyberark_session: "{{ cyberark_session }}"
```
