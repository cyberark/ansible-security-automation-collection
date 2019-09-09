cyberark_modules
================

Role to add CyberArk modules -- If not available from ansible core, or to get the latest.

Requirements
------------

- CyberArk Privileged Account Security Web Services SDK.
- CyberArk AIM Central Credential Provider

Role Variables
--------------

None.

Provided Modules
----------------

- **cyberark_authentication**: Module for CyberArk Vault Authentication using Privileged Account Security Web Services SDK
- **cyberark_user**: Module for CyberArk User Management using Privileged Account Security Web Services SDK
- **cyberark_account**: Module for CyberArk Account Management using Privileged Account Security Web Services SDK
- **cyberark_credential**: Module for CyberArk credential retrieval using Cyberark Central Credential Provider
 

Example Playbook
----------------

1) Example playbook showing the use of cyberark_authentication module for logon and logoff without using shared logon authentication.

```yaml
---
- hosts: localhost

  roles:

    - role: cyberark.modules

  tasks:

    - name: Logon to CyberArk Vault using PAS Web Services SDK
      cyberark_authentication:
        api_base_url: "https://components.cyberark.local"
        validate_certs: no
        username: "testuser"
        password: "Cyberark1"


    - name: Debug message
      debug:
        var: cyberark_session


    - name: Logoff from CyberArk Vault
      cyberark_authentication:
        state: absent
        cyberark_session: "{{ cyberark_session }}"

    - name: Debug message
      debug: var=cyberark_session
```


2) Example playbook showing the use of cyberark_user module to create a user.
```yaml
---
- hosts: localhost

  roles:

    - role: cyberark.modules

  tasks:

    - name: Logon to CyberArk Vault using PAS Web Services SDK
      cyberark_authentication:
        api_base_url: "https://components.cyberark.local"
        validate_certs: false
        use_shared_logon_authentication: true

    - name: Debug message
      debug:
        var: cyberark_session

    - name: Create User
      cyberark_user:
        username: "testuser2"
        initial_password: "Cyberark1"
        user_type_name: "EPVUser"
        change_password_on_the_next_logon: false
        group_name: "TestGroup"
        state: present
        cyberark_session: "{{ cyberark_session }}"
      register: cyberarkaction

    - debug: msg="{{cyberarkaction.cyberark_user.result}}"
      when: cyberarkaction.status_code == 201

    - name: Logoff from CyberArk Vault
      cyberark_authentication:
        state: absent
        cyberark_session: "{{ cyberark_session }}"

    - name: Debug message
      debug: var=cyberark_session
```


3) Example playbook showing the use of cyberark_user module to reset's a user credential.
```yaml
---
- hosts: localhost

  roles:

    - role: cyberark.modules

  tasks:

    - name: Logon to CyberArk Vault using PAS Web Services SDK
      cyberark_authentication:
        api_base_url: "https://components.cyberark.local"
        validate_certs: false
        use_shared_logon_authentication: true

    - name: Debug message
      debug:
        var: cyberark_session

    - name: Reset user credential
      cyberark_user:
        username: "testuser2"
        new_password: "Cyberark123"
        disabled: false
        state: present
        cyberark_session: "{{ cyberark_session }}"
      register: cyberarkaction

    - debug: msg="{{cyberarkaction.cyberark_user.result}}"
      when: cyberarkaction.status_code == 200

    - name: Logoff from CyberArk Vault
      cyberark_authentication:
        state: absent
        cyberark_session: "{{ cyberark_session }}"

    - name: Debug message
      debug: var=cyberark_session
```


4) Example playbook showing the use of cyberark_user module to add user to a group (only during creation).
```yaml
---
- hosts: localhost

  roles:

    - role: cyberark.modules

  tasks:

    - name: Logon to CyberArk Vault using PAS Web Services SDK
      cyberark_authentication:
        api_base_url: "https://components.cyberark.local"
        validate_certs: false
        use_shared_logon_authentication: true

    - name: Debug message
      debug:
        var: cyberark_session

    - name: Add user to group
      cyberark_user:
        username: "testuser2"
        initial_password: "Cyberark1"
        group_name: "TestGroup"
        state: present
        cyberark_session: "{{ cyberark_session }}"
      register: cyberarkaction

    - debug: msg="{{cyberarkaction}}"

    - name: Logoff from CyberArk Vault
      cyberark_authentication:
        state: absent
        cyberark_session: "{{ cyberark_session }}"

    - name: Debug message
      debug: var=cyberark_session
```


5) Example playbook showing the use of cyberark_user module to delete a user.
```yaml
---
- hosts: localhost

  roles:

    - role: cyberark.modules

  tasks:

    - name: Logon to CyberArk Vault using PAS Web Services SDK
      cyberark_authentication:
        api_base_url: "https://components.cyberark.local"
        validate_certs: false
        use_shared_logon_authentication: true

    - name: Debug message
      debug:
        var: cyberark_session

    - name: Remove  User
      cyberark_user:
        username: "testuser2"
        state: absent
        cyberark_session: "{{ cyberark_session }}"
      register: cyberarkaction

    - debug: msg="{{cyberarkaction}}"

    - name: Logoff from CyberArk Vault
      cyberark_authentication:
        state: absent
        cyberark_session: "{{ cyberark_session }}"

    - name: Debug message
      debug: var=cyberark_session
```


6) Example of a basic playbook showing the minimum needed to use the cyberark_credential module for retrieval of credentials using the Central Credential Provider.
```yaml
---
- hosts: localhost

  tasks:

    - name: credential retrieval basic
      cyberark_credential:
        api_base_url: "http://10.10.0.1"
        app_id: "TestID"
        query: "Safe=test;UserName=admin"
      register: {{ result }}
      no_log: true


    - name: Debug message
      debug: 
        var: {{ result }}
```


7) Example of a more advanced playbook outlining the use of all of the parameters available when using the cyberark_credential module for retrieval of credentials using the Central Credential Provider.
```yaml
---
- hosts: localhost
    
  tasks:

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
      no_log: true


    - name: Debug message
      debug: 
        var: {{ result }}
```

8) Example of playbook to provision a CyberArk Account.
```yaml
---
- hosts: localhost

  collections:
    - cyberark.bizdev

  tasks:

    - name: Logon to CyberArk Vault using PAS Web Services SDK
      cyberark_authentication:
        api_base_url: "https://components.cyberark.local"
        validate_certs: false
        use_shared_logon_authentication: true


    - name: Debug message
      debug:
        var: cyberark_session

    - name: Account
      cyberark_account:
        identified_by: "address,username"
        safe: "Test"
        address: "cyberark.local"
        username: "administrator"
        platform_id: WinServerLocal
        platform_account_properties:
            LogonDomain: "cyberark"
            OwnerName: "Edward Nunez"
        secret_management:
            automatic_management_enabled: false
            manual_management_reason: "This is just a test account"
        state: present
        cyberark_session: "{{ cyberark_session }}"
      register: cyberarkaction
      
    - name: Debug message
      debug:
        var: cyberarkaction

    - name: Logoff from CyberArk Vault
      cyberark_authentication:
        state: absent
        cyberark_session: "{{ cyberark_session }}"

    - name: Debug message
      debug: var=cyberark_session
```


License
-------

MIT

Author Information
------------------

- Cyberark Business Development Technical Team (BizDevTech@cyberark.com)
