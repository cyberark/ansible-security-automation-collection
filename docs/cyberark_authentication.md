# cyberark_authentication


Authenticates to CyberArk Vault using Privileged Account Security Web Services SDK and creates a session fact that can be used by other modules. It returns an Ansible fact called `cyberark_session`. Every module can use this fact as `cyberark_session` parameter.


#### Available Fields
```
options:
    state:
        default: present
        choices: [present, absent]
        description:
            - Specifies if an authentication logon/logoff and a cyberark_session should be added/removed.
    username:
        description:
            - The name of the user who will logon to the Vault.
    password:
        description:
            - The password of the user.
    new_password:
        description:
            - The new password of the user. This parameter is optional, and enables you to change a password.
    api_base_url:
        description:
            - A string containing the base URL of the server hosting CyberArk's Privileged Account Security Web Services SDK.
    validate_certs:
        type: bool
        default: 'yes'
        description:
            - If C(false), SSL certificates will not be validated.  This should only
              set to C(false) used on personally controlled sites using self-signed
              certificates.
    use_shared_logon_authentication:
        type: bool
        default: 'no'
        description:
            - Whether or not Shared Logon Authentication will be used.
    use_radius_authentication:
        type: bool
        default: 'no'
        description:
            - Whether or not users will be authenticated via a RADIUS server. Valid values are true/false.
    cyberark_session:
        description:
            - Dictionary set by a CyberArk authentication containing the different values to perform actions on a logged-on CyberArk session.
```
## Example Playbooks

**Shared Logon Authentication.**<br/>
Shared authentication is based on a user credential file that is stored in the PVWA web server. During shared authentication, only the user defined in the credential file can log on to the PVWA, but multiple users can use the logon token.

This type of authentication requires the playbook to manage the users as the Vault can't identify which specific user performs each action.

Multiple concurrent connections can be created using the same token, without affecting each other.

The shared user is defined in a user credential file, whose location is specified in the WSCredentialFile parameter, in the appsettings section of the PVWAweb.config file:

```xml
<add key="WSCredentialFile" value="C:\CyberArk\Password Vault Web Access\CredFiles\WSUser.ini"/>
```
> Make sure that this user can access the PVWA interface.<br/>
> Make sure the user only has the permissions in the Vault that they require.

It is recommended to secure connections between Ansible and the REST Web Services when using Shared Logon Authentication, using Client Authentication.

In addition to SSL, use Client Authentication to authenticate Ansible using a client certificate.

[Configuring client authentication via certificates](https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/Configuring%20Client%20Authentication%20via%20Client%20Certificates.htm)

```yaml
- name: Logon to CyberArk Vault using PAS Web Services SDK - use_shared_logon_authentication
  cyberark_authentication:
    api_base_url: "{{ web_services_base_url }}"
    use_shared_logon_authentication: yes
```

**CyberArk Authentication**<br/>
This method authenticates a user to the Vault and returns a token that can be used in subsequent web services calls. In addition, this method allows you to set a new password.

Users can authenticate using **CyberArk**, **LDAP** or **RADIUS** authentication.

```yaml
- name: Logon to CyberArk Vault using PAS Web Services SDK - Not use_shared_logon_authentication
  cyberark_authentication:
    api_base_url: "{{ web_services_base_url }}"
    username: "{{ password_object.password }}"
    password: "{{ password_object.passprops.username }}"
    use_shared_logon_authentication: no
```
**Logoff**<br/>
This method logs off the user and removes the Vault session.

```yaml
- name: Logoff from CyberArk Vault
  cyberark_authentication:
    state: absent
    cyberark_session: "{{ cyberark_session }}
```
