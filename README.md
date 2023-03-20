# Wazuh ChatGPT integration

 A configuration to allow Wazuh to communicate with ChatGPT, based on <https://loggar.hashnode.dev/augmenting-wazuh-with-chatgpt-integration>. All steps and images are taken from the website above. This repo is for mirroring and improvement purposes. Credits mainly go to the author of this integration: WhatDoesKmean?
 
 ![image](https://user-images.githubusercontent.com/50231698/226342392-1364916b-19d9-44a3-8493-51125199f85a.png)
 
 ![image](https://user-images.githubusercontent.com/50231698/226342473-c3f20ac4-71cb-479d-9f87-54d2e687a9de.png)


## Prerequisites

Before you can install the application, ensure that you have the following prerequisites installed on your machine:

- Python
- pip package manager
- Wazuh

## Installation

1. Clone the repository: `git clone https://github.com/AnonymousWP/Wazuh-ChatGPT-integration.git`
1. Install the required dependencies by running the following command: `pip install -r requirements.txt`

## Configuration

1. We need to create a rule that generates an alert when a non-private IP has attempted to log into our server. This allows us to distinguish malicious insiders and those attempting to gain access from outside the network.

    Open the Wazuh manager local rules file `/var/ossec/etc/rules/local_rules.xml` and add the below block:

    ```xml
    <!-- User Failed Authentication from Public IPv4 -->
    <group name="local,syslog,sshd,">
    <rule id="100004" level="10">
        <if_sid>5760</if_sid>
        <match type="pcre2">\b(?!(10)|192\.168|172\.(2[0-9]|1[6-9]|3[0-1])|(25[6-9]|2[6-9][0-9]|[3-9][0-9][0-9]|99[1-9]))[0-9]{1,3}\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)</match>
        <description>sshd: Authentication failed from a public IP address > $(srcip).</description>
        <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>
    </rule>
    </group>
    ```

    The `<match></match>` block of the rule specifies that we want to perform a REGEX search to "detect" an IP address within the log.

    If you prefer directly using the config, use [local_rules.xml](local_rules.xml)

1. This script will be saved in the `/var/ossec/integrations/` path of the Wazuh Manager as `custom-chatgpt.py`. The file execution permissions can be changed by the `chmod` command. Also, don't forget to use the `chown` command to change the file ownership as well. In this case:

    - `chmod 750 /var/ossec/integrations/custom-chatgpt.py`
    - `chown root:wazuh /var/ossec/integrations/custom-chatgpt.py`

1. Update the Wazuh manager configuration file (`/var/ossec/etc/ossec.conf`) using the integration block below:

    ```xml
    <!-- ChatGPT Integration -->
    <integration>
        <name>custom-chatgpt.py</name>
        <hook_url>https://api.openai.com/v1/chat/completions</hook_url>
        <api_key>YOUR-OWN-API-KEY</api_key>
        <level>10</level>
        <rule_id>100004</rule_id>
        <alert_format>json</alert_format>
    </integration>
    ```

    This instructs the Wazuh Manager to call the ChatGPT API endpoint anytime our rule id (100004), is triggered. You need to replace the `<api_key>` block with your own.
    Register for a free API key at <https://platform.openai.com/signup>

    If you prefer directly using the config, use [ossec.conf](ossec.conf)

1. Now, we need to capture the response sent back to the Wazuh Manager so we can observe the information gathered by our ChatGPT integration. Open the Wazuh Manager local rules file at `/var/ossec/etc/rules/local_rules.xml` and add the block below:

    ```xml
    <group name="local,syslog,sshd,">
    <rule id="100007" level="10">
        <field name="chatgpt.srcip">\.+</field>
        <description>IP address $(chatgpt.srcip) trying to connect to the network.</description>
        <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>
    </rule>
    </group>
    ```

    If you prefer directly using the config, use [local_rules.xml](local_rules.xml).

1. Restart Wazuh Manager
