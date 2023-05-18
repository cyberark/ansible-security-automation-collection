# Event-Driven Ansible

The CyberArk PAM Self-Hosted solution can be configured to export syslogs to Ansible as an event source. Once Ansible EDA ingests the event it will act on rule-based criteria contained in an Ansible Rulebook and will call Ansible Playbooks to initiate action when the conditions contained in the rulebook are met.

The following options will be available to configure CyberArk as Event Source:

**VAULT**
* CyberArk to Rsyslog to EDA Webhook
* CyberArk to Rsyslog to EDA Kafka Topic
* CyberArk Syslog as EDA event source (UDP Protocol)

**PTA**
* CyberArk PTA Syslog to EDA event source (UDP Protocol)


**NOTE**: For Rsyslog work, it was tested successfully with rsyslogd 8.2306.0.master (aka 2023.06) running on Ubuntu


## CyberArk to Rsyslog to EDA Webhook

![CyberArk to Rsyslog to EDA Webhook](https://github.com/cyberark/ansible-security-automation-collection/blob/master/docs/images/rsyslog-webhook.png?raw=true)

### Vault Configuration
Follow the steps under [Security Information and Event Management (SIEM) Applications](https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/PASIMP/DV-Integrating-with-SIEM-Applications.htm) documentation to setup the integration:

* Copy the [cyberark-eda-json-v1.0.xsl](https://github.com/cyberark/ansible-security-automation-collection/blob/master/plugins/event_source/cyberark-eda-json-v1.0.xsl) XSL Translator file to the Server\Syslog folder.
* See sample syslog configuration for DBPARM.ini below
* Recommended to use TCP and port 514 as it's default rsyslog port.

```
[SYSLOG]
UseLegacySyslogFormat=Yes
SyslogTranslatorFile=Syslog\cyberark-eda-json-v1.0.xsl
SyslogServerIP=<INSERT RSYSLOG IP HERE>
SyslogServerPort=514
SyslogServerProtocol=TCP
```

### Rsyslog server configuration to forward to event to webhook
Create a conf file in /etc/rsyslog.d/webhook.conf with the following content:
```
template(name="CyberarkFormat" type="string"
     string="%syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n")
module(load="omprog")
if ($hostname == 'VAULT') then
{
   action(type="omprog"
          binary="/tmp/run_curl.py"
          output="/tmp/output.log"
          template="CyberarkFormat")
}
```

Hostname will need be changed accordingly to your environment. If the syslog message are from a vault server, it will forward the event using the python script to the EDA webhook.

Here is an example of a python script to forward the information using the webhook:
```
#!/usr/bin/python
import urllib2
import sys
value = sys.stdin.readline()
file = open('/tmp/debug.txt', 'a')
file.write(value)
file.close
#data = '{"nw_src": "10.0.0.1/32", "nw_dst": "10.0.0.2/32", "nw_proto": "ICMP", "actions": "ALLOW", "priority": "10"}' #test data
data = value
url = 'http://ubuntu:5000/endpoint'
req = urllib2.Request(url, data, {'Content-Type': 'application/json'})
f = urllib2.urlopen(req)
for x in f:
    print(x)
f.close()
```

![Sample run of disable_pas_user_webhook.yml](https://github.com/cyberark/ansible-security-automation-collection/blob/master/docs/images/eda_disableuser_webhook.png?raw=true)

## CyberArk to Rsyslog to EDA Kafka Topic

![CyberArk to Rsyslog to EDA Kafka Topic](https://github.com/cyberark/ansible-security-automation-collection/blob/master/docs/images/rsyslog-kafka.png?raw=true)

### Vault Configuration
Follow the steps under [Security Information and Event Management (SIEM) Applications](https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/PASIMP/DV-Integrating-with-SIEM-Applications.htm) documentation to setup the integration:

* Copy the [cyberark-eda-json-v1.0.xsl](https://github.com/cyberark/ansible-security-automation-collection/blob/master/plugins/event_source/cyberark-eda-json-v1.0.xsl) XSL Translator file to the Server\Syslog folder.
* See sample syslog configuration for DBPARM.ini below
* Recommended to use TCP and port 514 as it's default rsyslog port.

```
[SYSLOG]
UseLegacySyslogFormat=Yes
SyslogTranslatorFile=Syslog\ansible-json-v1.0.xsl
SyslogServerIP=<INSERT RSYSLOG IP HERE>
SyslogServerPort=514
SyslogServerProtocol=TCP
```

### Rsyslog server configuration to forward to Kafka topic
Create a conf file in /etc/rsyslog.d/ansible_kafka.conf with the following content:

```
$EscapeControlCharactersOnReceive off
template(name="CyberarkFormat" type="string"
     string="%syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n")
if ($hostname == 'VAULT') then
{
    action(type="omkafka" broker=["ubuntu:9092"] topic="ansible" confParam="compression.codec=snappy" template="CyberarkFormat")
}
```

Hostname will need be changed accordingly to your environment. If the syslog message are from a vault server, it will forward to a Kafka topic on Kafka server in ubuntu on port 9092.

### Kafka Topic
Rsyslog use the omkafka plugin to forward the vault rsyslog to the Kafka topic. This plugin may need to be install by your admin as it's not enabled by default.
```
yum install rsyslog-kafka
```

Refer to Kafka documentation: https://kafka.apache.org/quickstart how to stand up a Kafka server and view topic.

![Sample rulebook](https://github.com/cyberark/ansible-security-automation-collection/blob/master/docs/images/eda_disableuser_kafka.png?raw=true)

The rulebook above listens on a Kafka ansible topic for suspended user and will disable the user and email admin via email.

## CyberArk Syslog as EDA event source (UDP Protocol)
This EDA plugin acts as a syslog listener on specific port using UDP bypassing the need of an existing rsyslog server.

![CyberArk Syslog as EDA event source (UDP Protocol)](https://github.com/cyberark/ansible-security-automation-collection/blob/master/docs/images/eda-syslog.png?raw=true)

Follow the steps under [Security Information and Event Management (SIEM) Applications](https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/PASIMP/DV-Integrating-with-SIEM-Applications.htm) documentation to setup the integration:


* Copy the [cyberark-eda-json-v1.0.xsl](https://github.com/cyberark/ansible-security-automation-collection/blob/master/plugins/event_source/cyberark-eda-json-v1.0.xsl) XSL Translator file to the Server\Syslog folder.
* See sample syslog configuration for DBPARM.ini below
* •	Currently only UDP is supported for the syslog event-source plugin

```
[SYSLOG]
UseLegacySyslogFormat=Yes
SyslogTranslatorFile=Syslog\ansible-json-v1.0.xsl
SyslogServerIP=<INSERT RSYSLOG IP HERE>
SyslogServerPort=1514
SyslogServerProtocol=UDP
```

![Sample rulebook](https://github.com/cyberark/ansible-security-automation-collection/blob/master/docs/images/eda_disable_user_syslog.png?raw=true)


## CyberArk PTA Syslog to EDA event source (UDP Protocol)

![CyberArk PTA Syslog to EDA event source (UDP Protocol)](https://github.com/cyberark/ansible-security-automation-collection/blob/master/docs/images/eda-pta-syslog.png?raw=true)

Please refer to the following documentation for instructions on how to setup PTA to sent data to SIEM:
[Send PTA syslog Records to SIEM](https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/PTA/Outbound-Sending-%20PTA-syslog-Records-to-SIEM.htm?tocpath=Administrator%7CComponents%7CPrivileged%20Threat%20Analytics%7CConfigure%20Privileged%20Threat%20Analytics%7CSend%20PTA%20Data%7CSend%20PTA%20syslog%20Records%20to%20SIEM%7C_____0)

In the PTA server's local systemparm.properties file have a line with:

```
syslog_outbound=[{\"siem\": \"SIEM\", \"format\": \"CEF\", \"host\": \"ANSIBLE_EDA_SERVER\", \"port\": << PORT FOR THE ANSIBLE EVENT-SOURCE EDA PLUGIN >>, \"protocol\": \"UDP\"}]
```

![Sample rulebook](https://github.com/cyberark/ansible-security-automation-collection/blob/master/docs/images/eda_pta_disable_user_syslog.png?raw=true)