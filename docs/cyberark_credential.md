# cyberark_credential

Creates a URI for retrieving a credential from a password object stored in the Cyberark Vault.  The request uses the Privileged Account Security Web Services SDK through the Central Credential Provider by requesting access with an Application ID.

**Requirements:**
- CyberArk AAM Central Credential Provider
- ApplicationID with the following permissions on the safe containing the credential being requested:
  - List Accounts
  - Retrieve Accounts
> **NOTE:** The CCP's Provider user (Prov_hostaname) needs to have the following permissions on the safe containing the credential being requested:
>> List Accounts<br>
>> Retrieve Accounts<br>
>> View Safe Members<br>

## Query
This field is semicolon delimited value that is the exact syntax that goes in the URI<br>
If you use the `object` parameter then there is no need to use any other parameter as the ObjectID is a unique value.<br>
**Example:**
```
    query: "Safe=test;UserName=admin"
      OR
    query: "Object=OperatingSystem-administrator-dev.local"
```

## Available Fields

```
options:
    api_base_url:
        description:
            - A string containing the base URL of the server hosting the Central Credential Provider
        required: true
        type: string
    validate_certs:
        description:
            - If C(false), SSL certificate chain will not be validated.  This should only set to C(true) if you have a root CA certificate installed on each node.
        type: bool
        required: false
        default: false
        type: bool
    app_id:
        description:
            - A string containing the Application ID authorized for retrieving the credential
        required: true
        type: string
    query:
        description:
            - A string containing details of the object being queried
        required: true
        parameters:
            Safe=<safe name>
            Folder=<folder name within safe>
            Object=<object name>
            UserName=<username of object>
            Address=<address listed for object>
            Database=<optional file category for database objects>
            PolicyID=<platform id managing object>
    connection_timeout:
        description:
            - An integer value of the allowed time before the request returns failed
        required: false
        default: '30'
        type: integer
    query_format:
        description:
            - The format for which your Query will be received by the CCP
        required: false
        default: 'Exact'
        choices: [Exact, Regexp]
        type: choice
    fail_request_on_password_change:
        description:
            - A boolean parameter for completing the request in the middle of a password change of the requested credential
        required: false
        default: false
        type: bool
    client_cert:
        description:
            - A string containing the file location and name of the client certificate used for authentication
        required: false
        type: string
    client_key:
        description:
            - A string containing the file location and name of the private key of the client certificate used for authentication
        required: false
        type: string
    reason:
        description:
            - Reason for requesting credential if required by policy
        required: false
        type: string
```



## Example Playbooks

```yaml
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
     
```
