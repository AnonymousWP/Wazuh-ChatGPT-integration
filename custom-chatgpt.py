#!/var/ossec/framework/python/bin/python3
# Copyright (C) 2015-2022, Wazuh Inc.
# ChatGPT Integration template by @WhatDoesKmean
# The below Python script takes the source IP that triggered our rule and sends it to the ChatGPT endpoint to get IP’s information and insights.

import json
import sys
import time
import os
from socket import socket, AF_UNIX, SOCK_DGRAM

try:
    import requests
    from requests.auth import HTTPBasicAuth
except Exception as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

# Global vars
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

print(pwd)
#exit()

json_alert = {}
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")
# Set paths
log_file = '{0}/logs/integrations.log'.format(pwd)
socket_addr = '{0}/queue/sockets/queue'.format(pwd)

def main(args):
    debug("# Starting")
    # Read args
    alert_file_location = args[1]
    apikey = args[2]
    debug("# API Key")
    debug(apikey)
    debug("# File location")
    debug(alert_file_location)

    # Load alert. Parse JSON object.
    with open(alert_file_location) as alert_file:
        json_alert = json.load(alert_file)
    debug("# Processing alert")
    debug(json_alert)

    # Request chatgpt info
    msg = request_chatgpt_info(json_alert,apikey)
    # If positive match, send event to Wazuh Manager
    if msg:
        send_event(msg, json_alert["agent"])

def debug(msg):
    if debug_enabled:
        msg = "{0}: {1}\n".format(now, msg)
    print(msg)
    f = open(log_file,"a")
    f.write(str(msg))
    f.close()


def collect(data):
  srcip = data['srcip']
  choices = data['content']
  return srcip, choices


def in_database(data, srcip):
  result = data['srcip']
  if result == 0:
    return False
  return True


def query_api(srcip, apikey):
  # Calling ChatGPT API Endpoint
  headers = {
        'Authorization': 'Bearer ' + apikey,
        'Content-Type': 'application/json',
    }

  json_data = {
        'model': 'gpt-3.5-turbo',
        'messages': [
            {
                'role': 'user',
                'content': 'Give me more data about this IP: ' + srcip,
            },
        ],
    }

  response = requests.post('https://api.openai.com/v1/chat/completions', headers=headers, json=json_data)

  if response.status_code == 200:
      # Create new JSON to add the IP
      ip = {"srcip": srcip}
      new_json = {}
      new_json = response.json()["choices"][0]["message"]
      new_json.update(ip)
      json_response = new_json

      data = json_response
      return data
  else:
      alert_output = {}
      alert_output["chatgpt"] = {}
      alert_output["integration"] = "custom-chatgpt"
      json_response = response.json()
      debug("# Error: The chatgpt encountered an error")
      alert_output["chatgpt"]["error"] = response.status_code
      alert_output["chatgpt"]["description"] = json_response["errors"][0]["detail"]
      send_event(alert_output)
      exit(0)


def request_chatgpt_info(alert, apikey):
    alert_output = {}
    # If there is no source ip address present in the alert. Exit.
    if not "srcip" in alert["data"]:
        return(0)

    # Request info using chatgpt API
    data = query_api(alert["data"]["srcip"], apikey)
    # Create alert
    alert_output["chatgpt"] = {}
    alert_output["integration"] = "custom-chatgpt"
    alert_output["chatgpt"]["found"] = 0
    alert_output["chatgpt"]["source"] = {}
    alert_output["chatgpt"]["source"]["alert_id"] = alert["id"]
    alert_output["chatgpt"]["source"]["rule"] = alert["rule"]["id"]
    alert_output["chatgpt"]["source"]["description"] = alert["rule"]["description"]
    alert_output["chatgpt"]["source"]["full_log"] = alert["full_log"]
    alert_output["chatgpt"]["source"]["srcip"] = alert["data"]["srcip"]
    srcip = alert["data"]["srcip"]

    # Check if chatgpt has any info about the srcip
    if in_database(data, srcip):
      alert_output["chatgpt"]["found"] = 1
    # Info about the IP found in chatgpt
    if alert_output["chatgpt"]["found"] == 1:
        srcip, choices = collect(data)

        # Populate JSON Output object with chatgpt request
        alert_output["chatgpt"]["srcip"] = srcip
        alert_output["chatgpt"]["choices"] = choices

        debug(alert_output)

    return(alert_output)


def send_event(msg, agent = None):
    if not agent or agent["id"] == "000":
        string = '1:chatgpt:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->chatgpt:{3}'.format(agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any", json.dumps(msg))

    debug(string)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()


if __name__ == "__main__":
    try:
        # Read arguments
        bad_arguments = False
        if len(sys.argv) >= 4:
            msg = '{0} {1} {2} {3} {4}'.format(now, sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else '')
            debug_enabled = (len(sys.argv) > 4 and sys.argv[4] == 'debug')
        else:
            msg = '{0} Wrong arguments'.format(now)
            bad_arguments = True

        # Logging the call
        f = open(log_file, 'a')
        f.write(str(msg) + '\n')
        f.close()

        if bad_arguments:
            debug("# Exiting: Bad arguments.")
            sys.exit(1)

        # Main function
        main(sys.argv)

    except Exception as e:
        debug(str(e))
        raise
