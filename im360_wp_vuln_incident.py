#!/usr/bin/python3.11

# Standard library imports
import argparse
import asyncio
from collections import defaultdict
from datetime import datetime
from itertools import chain
from typing import Dict
import json
import logging
from logging import config as loggingConfig
import os
import re
import sys
import yaml

# Third-party imports
import aiohttp
import aiosqlite
from pathvalidate import sanitize_filepath
import validators
#from tenacity import retry, stop_after_attempt, wait_fixed

INCIDENT_RESIDENT_FILE="/var/imunify360/imunify360-resident.db"
TIME_RESIDENT_FILE="time_resident_file"
VULN_WP_DB = "vuln_wp.db"
CONFIG_FILE = ".config.yaml"
SLACK_USERNAME = os.uname()[1]
LOG_FILE_PATH = "/var/log/im360incident_monitoring.log"
show_version = False

# coroutines for configuring logging
async def config_logging(dict_config):
    """ Configure logging. """
    loggingConfig.dictConfig(dict_config)
    logger = logging.getLogger("config_logging")
    logger.info("Logging configured.")

# coroutines for verifying required configuration entry in configuration file
async def verify_config(config_dict):
    """ Check the config file. """

    logger = logging.getLogger("verify_config")

    # Helper function to validate slack channel names
    def is_valid_slack_channel_name(channel_name):
        if channel_name.startswith('#'):
            channel_name = channel_name[1:]
        
        pattern = r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}$'
        return re.match(pattern, channel_name) is not None

    if not config_dict.get("config"):
        print("Warning: Configuration not found in .config file.")
        logger.warning("Configuration not found in .config file.")
        return None

    if not config_dict.get("config").get("notification"):
        print("Warning: Notification not found in .config file.")
        logger.warning("Notification not found in .config file")
        return None

    if not config_dict.get("config").get("notification").get("SLACK_WEBHOOKS_URL"):
        print("Warning: SLACK_WEBHOOKS_URL not found in .config file.")
        logger.warning("SLACK_WEBHOOKS_URL not found in .config file")
        return None
    
    if not validators.url(config_dict.get("config").get("notification").get("SLACK_WEBHOOKS_URL")):
        print("Warning: SLACK_WEBHOOKS_URL is not valid.")
        logger.warning("SLACK_WEBHOOKS_URL is not valid")
        return None

    if not config_dict.get("config").get("notification").get("SLACK_CHANNEL"):
        print("Warning: SLACK_CHANNEL not found in .config file.")
        logger.warning("SLACK_CHANNEL is not found in config file")
        return None
    
    slack_channel = config_dict.get("config").get("notification").get("SLACK_CHANNEL")
    if not is_valid_slack_channel_name(slack_channel):
        print("Warning: SLACK_CHANNEL is not valid.")
        logger.warning("SLAC_CHANNEL is not valid")
        return None

    return config_dict

# coroutines for sending notification to slack webhook
async def slack_webhook(webhook_url, channel, message):
    """ coroutines for sending to slack webhook """

    # define logger
    logger = logging.getLogger("slack_webhook")
    try:
        blocks = await create_blocks(message)
        await send_slack_message(webhook_url, channel, blocks)
    except (TypeError, ValueError) as e:
        logger.exception(f"Error: Wrong value type of json: {e}")
    except aiohttp.ClientPayloadError as e:
        logger.exception(f"Error: Payload error: {e}")
    except aiohttp.InvalidUrlClientError as e:
        logger.exception(f"Error: Invalid URL: {e}")
    except aiohttp.TooManyRedirects as e:
        logger.exception(f"Error: Too many redirects: {e}")

async def send_slack_message(webhook_url, channel, blocks):
    """ Couroutines for sending a message to slack webhook """
    logger = logging.getLogger("slack_webhook")
    slack_data = {
        "username": SLACK_USERNAME,
        "icon_emoji": ":firecracker:",
        "channel": channel,
        "attachments": [
            {
                "color": "#EBF400",
                "blocks": blocks
            }
        ]
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(webhook_url, json=slack_data) as response:
            if response.status == 200:
                logger.info("Message sent to Slack")
            else:
                logger.error(f"Response status {response.status} and reason {response.reason}")
                logger.error(f"Response text: {await response.text()}")

# coroutines for creating slack blocks
async def create_blocks(message):
    """ Create all blocks """
    blocks = await create_base_blocks(message)
    wp_version_block = await create_wp_version_block(message)
    blocks.extend(wp_version_block)
    wp_theme_plugin_block = await create_theme_plugin_blocks(message)
    blocks.extend(wp_theme_plugin_block)

    return blocks

# coroutines for creating base blocks
async def create_base_blocks(message):
    """ Create base blocks for slack message. """
    domain = message.get("domain", "Unknown")
    for item in message.get("data", []):
        vuln = "Yes" if any(
            v.get("vuln")
            for v in item.values()
            if isinstance(v, dict)) else "No"
        attacked = "Yes" if any(
            v.get("attacked")
            for v in item.values()
            if isinstance(v, dict)) else "No"
    
    return [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Vuln WP Possible* - {domain}"
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Vuln*: {vuln}\n*Attacked*: {attacked}"
            },
            "accessory": {
                "type": "image",
                "image_url": "https://a.slack-edge.com/production-standard-emoji-assets/14.0/google-large/1f525.png",
                "alt_text": "fire"
            }
        }
    ]

# coroutines for creating WP version block
async def create_wp_version_block(message):
    """ Create WP version block for slack message. """
    for item in message.get("data",[]):
        for value in item.values():
            if version := value.get("version"):
                return [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Core WP Version*: {version}"
                        }
                    }
                ]
    return []

# coroutines for creating theme and plugin blocks
async def create_theme_plugin_blocks(message):
    """ Create theme and plugin blocks for slack message. """
    blocks = []
    for item in message.get("data",[]):
        # print(f"item create theme plugins blocks: {item}")
        for key, value in item.items():
            if key in ["themes","plugins"]:
                info_key = f"{key}_info"
                for info in value.get(info_key, []):
                    blocks.append({
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*+++ {key} +++*"
                        },
                        "fields": await format_theme_plugin_info(info, key)
                    })
    return blocks

# coroutines for formating slack messages for theme and plugin information
async def format_theme_plugin_info(info, key):
    if version := info.get("version"):
        return [{
            "type": "mrkdwn",
            "text": f"*Name*:\n{info.get('name')}"
        },
        {
            "type": "mrkdwn",
            "text": f"*Version*:\n{version}"
        },
        {
            "type": "mrkdwn",
            "text": f"*Status*:\n{info.get('status')}"
        }]   
    else:
        return [{
            "type": "mrkdwn",
            "text": f"*Name*:\n{info.get('name')}"
        },
        {
            "type": "mrkdwn",
            "text": f"*Version*:\n{info.get(info.get('name'))}"
        }]

# calculate timestamp using to_thread
async def calculate_timestamp_resident_file(resident_file):
    """ Calculate the timestamp from resident file. """
    def getctime():
        os.sync()
        return os.path.getctime(resident_file)
    
    #return await asyncio.to_thread(lambda: os.path.getctime(resident_file))
    return await asyncio.to_thread(getctime)

# read current timestamp resident file using to_thread
async def read_timestamp_resident_file(resident_file):
    """ Read the timestamp from resident file. """
    logger = logging.getLogger("read_timestamp_resident_file")
    def read_file():
        os.sync()
        if os.path.exists(resident_file):
            with open(resident_file, "r") as f:
                try:
                    stored_time = f.read().strip()
                    if stored_time:
                        return float(stored_time)
                    else:
                        logger.error(f"{resident_file} is empty.","ERROR")
                except (ValueError, TypeError) as e:
                    logger.exception(f"Invalid data in {TIME_RESIDENT_FILE}: {e}")
        return None
    return await asyncio.to_thread(read_file)

# coroutines for updating timestamp of resident file at time resident file
async def update_timestamp_resident_file():
    """ Update the timestamp of resident file at time resident file. """
    timestamp = await calculate_timestamp_resident_file(INCIDENT_RESIDENT_FILE)
    with open(TIME_RESIDENT_FILE, "w") as f:
        f.write(str(timestamp))
    return True

# coroutines for checking tasks
async def check_for_tasks():
    """ Check for tasks. """

    # define logger
    logger = logging.getLogger("check_for_tasks")

    # Get the timestamp from resident file
    def file_exists(file_path):
        return os.path.exists(file_path)
    
    if not await asyncio.to_thread(file_exists, INCIDENT_RESIDENT_FILE):
        logger.error(f"{INCIDENT_RESIDENT_FILE} not found.")
        return False
    
    # Calculate the timestamp from resident f   ile
    current_time = await calculate_timestamp_resident_file(INCIDENT_RESIDENT_FILE)
    if current_time is None:
        logger.error("Failed to retrieve the current timestamp of the incident file.")
        return False

    stored_time = await read_timestamp_resident_file(TIME_RESIDENT_FILE)
    if stored_time is None:
        # Update the timestamp in resident file
        logger.info("No valid stored timestamp found,. creating it...")
        await update_timestamp_resident_file()
        return False

    # Check if the timestamp has been updated
    if current_time > stored_time:
        logger.info("Incident file has changed, Task available.")
        await update_timestamp_resident_file()
        return True
    else:
        #logger.info("No task available.")
        return False

# validate since argument
def is_valid_since(since):
    pattern = r"^\d+\s+(second|minute|hour|day|week|month|year)s?\s*"

    return re.match(pattern, since) is not None

# validate domain argument
def is_valid_domain(domain):
    pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, domain) is not None

# functions for set argument
def setArgument():
    # parse the argument
    parser = argparse.ArgumentParser(
        description="Imunify360 Addon Command for checking incident from CLI"
    )
    parser.add_argument("-d", "--domain", help="Specify domain name", required=False)
    parser.add_argument("-s", "--since", help="the timestamp from", required=True)
    args = parser.parse_args()
    
    if args.domain:
        if not is_valid_domain(args.domain):
            parser.error(f"Invalid domain name: {args.domain}")
    
    if args.since:
        if not is_valid_since(args.since):
            parser.error(f"Invalid since argument: {args.since}")

    # if the length of argument only one, then print help and exit the program with exitcode 1
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    return args

# Coroutines for creating database
async def create_vuln_wp_database():
    """ Create database for storing incident data from imunify360 resident file """

    # define logger
    logger = logging.getLogger("create_vuln_wp_database")

    try:
        query = """
            CREATE TABLE IF NOT EXISTS vuln_wp_status (
                        domain TEXT PRIMARY KEY,
                        timestamp REAL,
                        modifying_date REAL,
                        core_wp_vuln BOOLEAN,
                        themes_vuln TEXT,
                        plugins_vuln TEXT,
                        notification_sended_time REAL
            )
        """
        async with aiosqlite.connect(VULN_WP_DB) as wp_vuln_db:
            logger.info("Create vuln_wp.db database.")
            await wp_vuln_db.execute(query)
            await wp_vuln_db.commit()
        return True
    except aiosqlite.Error as e:
        logger.exception(f"An error occurred: {e}")
        return False

# Coroutines for getting data from incident resident file
async def get_data_incident_im360(domain=None, since="4 hours ago"): 
    # open rule_vuln_wp.json

    logger = logging.getLogger("get_data_incident_im360")

    try:
        with open("rule_vuln_wp.json") as r:
            # get all rule id related to wordpress vulnerability
            # then create parameterized placeholder based on all the rules
            data_dict = json.load(r)
            rule_values = data_dict.get("rule", [])
            async with aiosqlite.connect(INCIDENT_RESIDENT_FILE) as conn_im360:
                #cursor_im360 = conn_im360.cursor()

                placeholders = ", ".join(["?" for _ in rule_values])

                # if domain is defined, get incident list based on the domain and since time
                if domain:
                    args = [domain, "-{}".format(since)] + rule_values
                    query = f"SELECT timestamp,name,description,abuser,domain,rule,severity,retries FROM incident WHERE domain=? AND timestamp >= strftime('%s', 'now', ?) AND rule IN ({placeholders})"
                else:
                    # if domain is not defined get all incident list based on since time
                    args = ["-{}".format(since)] + rule_values
                    query = f"SELECT timestamp,name,description,abuser,domain,rule,severity,retries FROM incident WHERE timestamp >= strftime('%s', 'now', ?) AND rule IN ({placeholders})"

                # execute q uery with prepared statement
                #rows = cursor_im360.execute(query, args)
                async with conn_im360.execute(query, args) as cursor:
                    while True:
                        rows = await cursor.fetchmany(3)
                        if not rows:
                            break
                        yield rows
                #    async for row in cursor:
                #        print(row)

                # get the domain name from the row, then find the username of cpanel, and check if there is wordpress vulnerability related to the incident attack
                # for row in rows:
    except aiosqlite.Error as e:
        logger.exception(f"An error occurred: {e}")
        yield False

# Coroutines for getting domain and username
async def get_domain_username(row):
    """ Get the domain name and username. """

    logger = logging.getLogger("get_domain_username")
    
    username = None
    try:
        # Get the username of the cPanel account
        domain = row[4].replace("www.", "")
        cmd = ["/usr/local/cpanel/scripts/whoowns", domain]
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        username, stderr  = await process.communicate()
        if process.returncode != 0:
            if stderr:
                logger.error(f"Error command for getting username failled: {process.returncode} with {stderr}")
            return False, None
        username = username.decode("utf-8").rstrip()
        return domain, username
    except asyncio.TimeoutError:
        logger.exception("Async timeout error occurred.")
        return False, None
    except OSError as e:
        logger.exception(f"Error command for getting username failled: {e}")
        return False, None

# Coroutines for getting document root
async def get_document_root(domain):
    """ get document root of the domain """

    logger = logging.getLogger("get_document_root")

    try:
        # define the command for getting document root
        cmd = [
            "/usr/local/cpanel/bin/whmapi1",
            "domainuserdata",
            f"domain={domain}",
            "--output=json",
        ]
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # load the json result as dict
        result, stderr = await process.communicate()
        if process.returncode == 0 and result:
            data = json.loads(result.decode("utf-8").rstrip())
            if "data" in data:
                if data["data"]:
                    return data["data"]["userdata"]["documentroot"]
                else:
                    logger.error("Warning: cannot get result!")
                    return None
            else:
                logger.error("Warning: cannot get result!")
                return None
        else:
            if stderr:
                logger.error("Warning: cannot get result with error {stderr}!")
            return None
    except asyncio.TimeoutError:
        logger.exception("Timeout error occurred.")
        return None
    except OSError as e:
        logger.exception(f"Error command for getting document root failled: {e}")
        return None

# coroutines for checking if vuln api provider have been set at wp-config.php
async def check_vuln_api_provider_set(doc_root):
    """ Check if the vuln api provider is set or not. """

    logger = logging.getLogger("check_vuln_api_provider_set")

    try:
        if os.path.exists(os.path.join(doc_root, "wp-config.php")):
            with open(os.path.join(doc_root, "wp-config.php"), "r") as f:
                content = f.read()
                return "define('VULN_API_PROVIDER',getenv('VULN_API_PROVIDER'));" in content
            return False
        else:
            logger.error(f"Warning: {doc_root}/wp-config.php not found.")
            return False

    except asyncio.TimeoutError:
        logger.exception("Timeout error occurred.")
        return None
    except OSError as e:
        logger.exception(f"Error command for getting vuln api provider failled: {e}")
        return None


# Coroutines for installing WP CLI Vulnerability Scanner
async def install_wp_vuln_scanner(username, doc_root):
    """ install WP CLI Vunlnerability Scanner to specific username """

    logger = logging.getLogger("install_wp_vuln_scanner")

    try:
        if not os.path.exists("/home/{}/.bin/wp".format(username)) or not os.path.exists(f"/home/{username}/.wp-cli/packages") or not await check_vuln_api_provider_set(doc_root):
            cmd = ["/opt/imunify360_wp_vuln_incident/wp-cli-vuln-scanner-installer/install_wp_cli_vuln_scanner", "-u", username]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await process.communicate()
            if process.returncode == 0:
                logger.info("WP CLI Vulnerability Scanner installed successfully.")
                return True
            else:
                if stderr:
                    logger.error(f"WP CLI Vulnerability Scanner installation failed with error {stderr}!")
                return False
    except asyncio.TimeoutError:
        logger.exception("Timeout error occurred.")
        return None
    except OSError as e:
        logger.exception(f"Error command for getting document root failled: {e}")
        return None

# Coroutines for scanning the core of wordpress
async def wp_vuln_core_wp_scanning(username, doc_root):
    """ Scanning the core of wordpress """
    pattern = "WordPress Core < \\S+"
    
    os.environ["VULN_API_PROVIDER"] = "wordfence"
    os.environ["WP_CLI_PACKAGES_DIR"] = f"/home/{username}/.wp-cli/packages"

    # define loger
    logger = logging.getLogger("wp_vuln_core_wp_scanning")

    # command for scanning core wp vuln
    cmd = [
        "/usr/sbin/cagefs_enter_user",
        username,
        f"/home/{username}/.bin/wp",
        f"--path={doc_root}",
        "vuln",
        "core-status",
        "--format=json",
    ]

    try:    
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        logger.info(f"Scanning vulnerability of WordPress core in {doc_root} for {username} in progress...")
        stdout, stderr = await process.communicate()
        # check process return code and valid output
        if process.returncode == 0 and stdout:
            try:
                data = json.loads(stdout.decode("utf-8").strip())
                # print(f"data: {data}")
                matches = [
                    match.group()
                    for item in data
                    if isinstance(item, dict) and item.get("status")
                    for match in [re.search(pattern, item["status"])]
                    if match
                ]
                logger.info(f"Scanning vulnerability of wp core in {doc_root} for {username} completed.")
                return matches if matches else None
            except json.JSONDecodeError as e:
                logger.exception(f"Error decoding JSON: {e}")
                return None
        else:
            if stderr:
                logger.error(f"Command failed with return code {process.returncode} with {stderr}")
            return None
    
    except asyncio.TimeoutError:
        logger.exception("Timeout error occurred.")
        return None
    except OSError as e:
        logger.exception(f"Error command for scanning core wp failled: {e}")
        return None

# Coroutines for getting the title of the theme
async def wp_get_theme_title(username, theme, doc_root):
    """ Get the title of the theme. """

    logger = logging.getLogger("get_theme_title")

    cmd = [
        "/usr/sbin/cagefs_enter_user",
        username,
        f"/home/{username}/.bin/wp",
        f"--path={doc_root}",
        "theme",
        "get",
        theme,
        "--field=title",
    ]
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode == 0 and stdout:
            return stdout.decode("utf-8").rstrip()
        else:
            if stderr:
                logger.error(f"Error command for getting theme title failled with {stderr}")
            return None
    except asyncio.TimeoutError:
        logger.exception("Timeout error occurred.")
        return None
    except OSError as e:
        logger.exception(f"Error command for getting theme title failled: {e}")
        return None

# coroutines for getting the title of the plugin
async def wp_get_plugin_title(username, plugin, doc_root):
    """ Get the title of the plugin. """

    # define logger
    logger = logging.getLogger("wp_get_plugin_title")

    cmd = [
        "/usr/sbin/cagefs_enter_user",
        username,
        f"/home/{username}/.bin/wp",
        f"--path={doc_root}",
        "plugin",
        "get",
        plugin,
        "--field=title",
    ]
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, stderr = await process.communicate()

        if process.returncode == 0 and stdout:
            return stdout.decode("utf-8").rstrip()
        else:
            if stderr:
                logger.error(f"Error command for getting plugin title failled with {stderr}")
            return None
    except asyncio.TimeoutError:
        logger.exception("Timeout error occurred.")
        return None
    except OSError as e:
        logger.exception(f"Error command for getting plugin title failled: {e}")
        return None
    
# coroutines for getting the version of plugin
async def wp_get_plugin_version(username, plugin, doc_root):
    """ Get the title of the plugin. """

    # define logger
    logger = logging.getLogger("wp_get_plugin_version")

    cmd = [
        "/usr/sbin/cagefs_enter_user",
        username,
        f"/home/{username}/.bin/wp",
        f"--path={doc_root}",
        "plugin",
        "get",
        plugin,
        "--field=version",
    ]
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, stderr = await process.communicate()

        if process.returncode == 0 and stdout:
            return stdout.decode("utf-8").rstrip()
        else:
            if stderr:
                logger.error(f"Error command for getting plugin version failled with {stderr}")
            return None
    except asyncio.TimeoutError:
        logger.exception("Timeout error occurred.")
        return None
    except OSError as e:
        logger.exception(f"Error command for getting plugin version failled: {e}")
        return None

# coroutines for getting the version of theme
async def wp_get_theme_version(username, theme, doc_root):
    """ Get the title of the plugin. """

    # define logger
    logger = logging.getLogger("wp_get_theme_version")

    cmd = [
        "/usr/sbin/cagefs_enter_user",
        username,
        f"/home/{username}/.bin/wp",
        f"--path={doc_root}",
        "theme",
        "get",
        theme,
        "--field=version",
    ]
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, stderr = await process.communicate()

        if process.returncode == 0 and stdout:
            return stdout.decode("utf-8").rstrip()
        else:
            if stderr:
                logger.error(f"Error command for getting theme version failled with {stderr}")
            return None
    except asyncio.TimeoutError:
        logger.exception("Timeout error occurred.")
        return None
    except OSError as e:
        logger.exception(f"Error command for getting theme version failled: {e}")
        return None

# coroutines for processing status output
async def process_status_output(username, doc_root, type, list_vuln, show_version):
    """ Process the status output. """
    combined_apps = defaultdict(lambda: {"status": []})

    # print(list_vuln)
    # print(f"list vuln {type} : {list_vuln}")
    for app in list_vuln:
        name = app.get("name")
        version = app.get("installed version")
        severity = app.get("severity")

        if severity and severity != "n/a":
            status = f"*[* {app.get('status')}, *severity*: {severity}, *fixed in*: {app.get('fixed in')} *]*\n"
            key = (name, version)

            combined_apps[key].update({"name": name, "version": version})
            combined_apps[key]["status"].append(status)
            # print(f"combined_apps {type}: {combined_apps}")

    filtered_apps = [
        { 
            "name": app.get("name"),
            "version": app.get("version"),
            "status": " ".join(app.get("status"))
        }
        for app in combined_apps.values()
    ]

    if type == "theme":
        list_vuln_theme_title = await asyncio.gather(
            *[wp_get_theme_title(username, vuln_theme.get("name"), doc_root) for vuln_theme in filtered_apps]
        )
        list_vuln_theme_name = [vuln_theme.get("name") for vuln_theme in filtered_apps]
        return {"status": "success", "data": { "name": list_vuln_theme_name, "themes": filtered_apps, "title": list_vuln_theme_title}}
    elif type == "plugin":
        list_vuln_plugin_title = await asyncio.gather(
            *[wp_get_plugin_title(username, vuln_plugin.get("name"), doc_root) for vuln_plugin in filtered_apps]
        )
        list_vuln_plugin_name = [vuln_plugin.get("name") for vuln_plugin in filtered_apps]
        return {"status": "success", "data": { "name": list_vuln_plugin_name, "plugins": filtered_apps, "title": list_vuln_plugin_title}}

# coroutines for processing standard output
async def process_standard_output(username, doc_root, type, list_vuln, show_version):

    """ show standard output """
    if type == "theme":
        list_vuln_theme_title = await asyncio.gather(
            *[wp_get_theme_title(username, vuln_theme, doc_root) for vuln_theme in list_vuln]
        )

        if show_version:
            list_vuln_theme_version = await asyncio.gather(
                *[wp_get_theme_version(username, vuln_theme, doc_root) for vuln_theme in list_vuln]
            )
            theme_info = dict(zip(list_vuln,list_vuln_theme_version))
            return {"status": "success", "data": { "name": list_vuln, "themes": theme_info, "title": list_vuln_theme_title}}
        else:
            return {"status": "success", "data": { "name": list_vuln, "title": list_vuln_theme_title}}
    elif type == "plugin":
        list_vuln_plugin_title = await asyncio.gather(
            *[wp_get_plugin_title(username, vuln_plugin, doc_root) for vuln_plugin in list_vuln]
        )

        if show_version:
            list_vuln_plugin_version = await asyncio.gather(
                *[wp_get_plugin_version(username, vuln_plugin, doc_root) for vuln_plugin in list_vuln]
            )
            plugin_info = dict(zip(list_vuln,list_vuln_plugin_version))
            return {"status": "success", "data": { "name": list_vuln, "plugins": plugin_info, "title": list_vuln_plugin_title}}
        else:
            return {"status": "success", "data": { "name": list_vuln, "title": list_vuln_plugin_title}} 

# coroutines for scanning vulnerabilities of wordpress themes
async def wp_vuln_theme_scanning(username, doc_root, show_version=False, show_status=False):
    """ Scan the themes of wordpress. """

    # define logger
    logger = logging.getLogger("wp_vuln_theme_scanning")

    os.environ["VULN_API_PROVIDER"] = "wordfence"
    os.environ["WP_CLI_PACKAGES_DIR"] = f"/home/{username}/.wp-cli/packages"
    
    if show_status:
        cmd = [
            "/usr/sbin/cagefs_enter_user",
            username,
            f"/home/{username}/.bin/wp",
            f"--path={doc_root}",
            "vuln",
            "theme-status",
            "--format=json",
        ]
    else:
        cmd = [
            "/usr/sbin/cagefs_enter_user",
            username,
            f"/home/{username}/.bin/wp",
            f"--path={doc_root}",
            "vuln",
            "theme-status",
            "--porcelain",
        ]

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        logger.info(f"Scanning vulnerability of WordPress themes in {doc_root} for {username} in progress...")
        stdout, stderr = await process.communicate()

        if process.returncode == 0 and stdout:
            list_vuln_theme_title = []
            if show_status:
                list_vuln_theme = json.loads(stdout.decode("utf-8"))
            else:
                list_vuln_theme = stdout.decode("utf-8").strip().split("\n")

            logger.info(f"Scanning vulnerability of WordPress themes in {doc_root} for {username} completed.")

            if not list_vuln_theme:
                return None

            if show_status:
                return await process_status_output(username, doc_root, "theme", list_vuln_theme, show_version)
            else:
                return await process_standard_output(username, doc_root, "theme", list_vuln_theme, show_version)
            
        else:
            if stderr:
                logger.error(f"Error command for getting wp vuln theme failed with {stderr}")
                return {"status": "failed", "data": None}
            return None
    except asyncio.TimeoutError:
        logger.exception("Timeout error occurred.")
        return {"status": "failed", "data": None}
    except OSError as e:
        logger.exception(f"Error command for getting wp vuln theme failled: {e}")
        return {"status": "failed", "data": None}

# coroutines for scanning vulnerabilities of wordpress plugins
async def wp_vuln_plugin_scanning(username, doc_root, show_version=False, show_status=False):
    """ Scan the plugins of wordpress """

    # define logger
    logger = logging.getLogger("wp_vuln_plugin_scanning")

    os.environ["VULN_API_PROVIDER"] = "wordfence"
    os.environ["WP_CLI_PACKAGES_DIR"] = f"/home/{username}/.wp-cli/packages"
    if show_status:
        cmd = [
            "/usr/sbin/cagefs_enter_user",
            username,
            f"/home/{username}/.bin/wp",
            f"--path={doc_root}",
            "vuln",
            "plugin-status",
            "--format=json",
        ]
    else:
        cmd = [
            "/usr/sbin/cagefs_enter_user",
            username,
            f"/home/{username}/.bin/wp",
            f"--path={doc_root}",
            "vuln",
            "plugin-status",
            "--porcelain",
        ]

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        logger.info(f"Scanning vulnerability of WordPress plugins in {doc_root} for {username} in progress...")
        stdout, stderr = await process.communicate()

        if process.returncode == 0 and stdout:
            # print(f"show status vuln plugin scan: {show_status}")
            if show_status:
                list_vuln_plugin = json.loads(stdout.decode("utf-8"))
                # print(f"list vuln plugin: {list_vuln_plugin}")
            else:
                list_vuln_plugin = stdout.decode("utf-8").strip().split("\n")
            
            logger.info(f"Scanning vulnerability of WordPress plugins in {doc_root} for {username} completed.")

            if not list_vuln_plugin:
                return None

            if show_status:
                return await process_status_output(username, doc_root, "plugin", list_vuln_plugin, show_version)
            else:
                return await process_standard_output(username, doc_root, "plugin", list_vuln_plugin, show_version)
        else:
            if stderr:
                logger.error(f"Error command for getting wp vuln plugin failled with {stderr}")
                return {"status": "failed", "data": None}
            return None
    except asyncio.TimeoutError:
        logger.exception("Timeout error occurred.")
        return {"status": "failed", "data": None}
    except OSError as e:
        logger.exception(f"Error command for getting wp vuln plugin failled: {e}")
        return {"status": "failed", "data": None}
    
# Coroutine for getting the core version of wordpress
async def wp_core_version(username, doc_root):
    """ Get the core version of wordpress. """

    # define logger
    logger = logging.getLogger("wp_core_version")

    cmd = [
        "/usr/sbiun/cagefs_enter_user",
        username,
        f"/home/{username}/.bin/wp",
        f"--path={doc_root}",
        "core",
        "version",
    ]

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode == 0 and stdout:
            return stdout.decode("utf-8").strip()
        else:
            if stderr:
                logger.error(f"Error command for getting core version failled with {stderr}")
            return None
    except asyncio.TimeoutError:
        logger.exception("Timeout error occurred.")
        return None
    except OSError as e:
        logger.exception(f"Error command for getting core version failled: {e}")
        return None

# coroutines for checking vulnerability dictionary variable and dumps to json
async def check_vuln_dict(vuln_dict,vuln_themes,vuln_plugins):
    """ Check if the vuln_dict is empty or not. """
    if vuln_dict:
        if vuln_themes:
            # convert dict of vuln_themes to json
            vuln_themes = json.dumps(vuln_themes)
        if vuln_plugins:
            # convert dict of vuln_plugins to json
            vuln_plugins = json.dumps(vuln_plugins)

        return vuln_themes, vuln_plugins
    else:
        return None, None

# coroutines for updating wp vuln db
async def update_wp_vuln_db(*, connection, query, arg=None):
    """ Update the wp vuln db. """

    # define logger
    logger = logging.getLogger("update_wp_vuln_db")

    if arg:
        try:
            logger.info("Update WordPress Vulnerability Information to database wp_vuln.db")
            await connection.execute(
                query,
                arg,
            )
            await connection.commit()
            logger.info("Update WordPress Vulnerability Information to database wp_vuln.db completed.")
            return True
        except aiosqlite.Error as e:
            logger.exception(f"An error occurred: {e}")
            return False
    else:
        try:
            await connection.execute(
                query,
            )
            await connection.commit()
            return True
        except aiosqlite.Error as e:
            logger.exception(f"An error occurred: {e}")
            return False

# coroutines for checking vuln wp from vuln wp db
async def check_vuln_from_wp_db(*,username,doc_root,incident_desc,result, show_version=False):
    """ Check vuln from wp db. """

    # define logger
    logger = logging.getLogger("check_vuln_from_wp_db")

    vuln_dict = {}
    if result:
        last_entry = result[-1]
        if last_entry and last_entry[0]:
            core_vuln, themes_vuln, plugins_vuln = last_entry[2:5]

            if core_vuln:
                vuln = True
                core_version_vuln = await wp_core_version(username,doc_root)

                if show_version:
                    if any(f"WordPress Core {op} {core_version_vuln}" in core_vuln for op in ["<","<="]):
                        vuln_dict["core_wp"] = {"vuln": vuln, "attacked": True, "core_version": core_version_vuln}
                else:
                    if any(f"WordPress Core {op} {core_version_vuln}" in core_vuln for op in ["<","<="]):
                        vuln_dict["core_wp"] = {"vuln": True, "attacked": True}

            if themes_vuln:
                vuln = True
                vuln_themes = json.loads(themes_vuln)
                if vuln_themes.get("themes"):
                    if any(v_themes in incident_desc for v_themes in chain(vuln_themes.get("name"),vuln_themes.get("title"))):
                        vuln_dict["themes"] = {"vuln": vuln, "attacked": True, "themes_info": vuln_themes.get("themes")}
                else:
                    if any(v_themes in incident_desc for v_themes in chain(vuln_themes.get("name"),vuln_themes.get("title"))):
                        vuln_dict["themes"] = {"vuln": True, "attacked": True}

            if plugins_vuln:
                vuln = True
                vuln_plugins = json.loads(plugins_vuln)
                if vuln_plugins.get("plugins"):
                    if any(v_plugins in incident_desc for v_plugins in chain(vuln_plugins.get("name"),vuln_plugins.get("title"))):
                        vuln_dict["plugins"] = {"vuln": vuln, "attacked": True, "plugins_info": vuln_plugins.get("plugins")}
                else:
                    if any(v_plugins in incident_desc for v_plugins in chain(vuln_plugins.get("name"),vuln_plugins.get("title"))):
                        vuln_dict["plugins"] = {"vuln": True, "attacked": True}

    return vuln_dict    

# coroutines for validating wp vuln result
async def validate_wp_vuln(*,domain, timestamp_now, combined_modifying_date, vuln, vuln_dict, vuln_core_wp, vuln_plugins, vuln_themes, connection):
    """ process wp vuln and update to wp vuln db. """

    # logger = logging.getLogger("validate_wp_vuln")

    if vuln:
        if vuln_plugins != "failed" and vuln_themes != "failed":
            vuln_themes = vuln_themes.get("data") if vuln_themes else ""
            vuln_plugins = vuln_plugins.get("data") if vuln_plugins else ""
            vuln_themes, vuln_plugins = await check_vuln_dict(
                vuln_dict, 
                vuln_themes, 
                vuln_plugins
            )
            
            arg = tuple(
                    (
                        domain,
                        timestamp_now,
                        combined_modifying_date,
                        vuln_core_wp,
                        vuln_themes,
                        vuln_plugins,
                    )
            )
            await update_wp_vuln_db(connection=connection,
                query = """
                    INSERT OR REPLACE INTO vuln_wp_status (
                        domain, timestamp, modifying_date, core_wp_vuln, themes_vuln, plugins_vuln
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                arg = arg,
            )

            return vuln_dict
        else:
            return None
    else:
        # if vuln is empty thenp
        # define the same tuple but vuln_themes and vuln_plugins is not using json, usually it is empty string
        if vuln_plugins != "failed" and vuln_themes != "failed":
            vuln_themes = vuln_themes.get("data") if vuln_themes else ""
            vuln_plugins = vuln_plugins.get("data") if vuln_plugins else ""
            arg = tuple(
                (
                    domain,
                    timestamp_now,
                    combined_modifying_date,
                    vuln_core_wp,
                    vuln_themes,
                    vuln_plugins,
                )
            )

            await update_wp_vuln_db(connection=connection,
                query = """
                INSERT OR REPLACE INTO vuln_wp_status (domain, timestamp, modifying_date, core_wp_vuln, themes_vuln, plugins_vuln)
                        VALUES (?, ?, ?, ?, ?, ?)
                """,
                arg = arg,
            )

        return None

# coroutines for processing vuln result
async def process_vuln(vuln_result,key,row,username,doc_root,show_version="False"):
    """ process vuln result """
    vuln = None
    vuln_core_wp = False
    vuln_dict = {}

    # Helper functions for processing vuln result themes and plugins
    async def check_vulnerability(vuln_data, key, vuln_dict):
        nonlocal vuln
        if vuln_data is None:
            return ""

        if vuln_data.get("status") == "success":
            if data := vuln_data.get("data"):
                vuln = True
                if data.get("themes" if key == "themes" else "plugins"):
                    if any(
                        v in row[2]
                        for v in chain(data.get("name"), data.get("title"))
                    ):
                        vuln_dict[key] = {"vuln": vuln, "attacked": True, f"{key}_info": data.get("themes" if key == "themes" else "plugins")}
                        return vuln_data
                else:
                    if any(
                        v in row[2]
                        for v in chain(data.get("name"), data.get("title"))
                    ):
                        vuln_dict[key] = {"vuln": vuln, "attacked": True}
                        return vuln_data
            else:
                return ""
        else:
            return "failed"

    # Check core WP status
    if key == "core":
        if vuln_core_wp_status := locals().get('vuln_core_wp_status'):
            core_version_vuln = await wp_core_version(username, doc_root)
            if any(v_core in row[2] for v_core in vuln_core_wp_status):
                vuln_dict["core_wp"] = {"vuln": True, "attacked": True, "version": core_version_vuln if show_version else None}
                vuln = True
                vuln_core_wp = True

                return vuln, vuln_core_wp, vuln_dict

    if theme_status := await check_vulnerability(vuln_result,key,vuln_dict):
        return vuln, theme_status, vuln_dict

    if plugin_status := await check_vulnerability(vuln_result,key,vuln_dict):
        return vuln, plugin_status, vuln_dict

    return None, None, vuln_dict

# coroutins for full vulnerability scan
async def full_vuln_scan(*, username, domain, doc_root, row, combined_modifying_date, connection, show_version=False,show_status=False, scan_concurrent=False):
    """ Full vulnerability scan for wordpress """

    logger = logging.getLogger("full_vuln_scan")

    try:
        vuln = None
        vuln_dict = {}

        # Check if scan_concurrent configuration active
        if scan_concurrent:
            # Task Group of each scanning process
            async with asyncio.TaskGroup() as tg_vuln:
                core_task = tg_vuln.create_task(wp_vuln_core_wp_scanning(username, doc_root))
                theme_task = tg_vuln.create_task(wp_vuln_theme_scanning(username, doc_root, show_version=show_version, show_status=show_status))
                plugin_task = tg_vuln.create_task(wp_vuln_plugin_scanning(username, doc_root, show_version=show_version, show_status=show_status))

            # Process their results
            vuln_core_wp_status = core_task.result()
            vuln_themes = theme_task.result()
            vuln_plugins = plugin_task.result()

            # Process the vuln result using Task Group
            async with asyncio.TaskGroup() as tg_result:
                core_result = tg_result.create_task(process_vuln(vuln_core_wp_status,"core",row,username,doc_root,show_version))
                theme_result = tg_result.create_task(process_vuln(vuln_themes,"themes",row,username,doc_root,show_version))
                plugin_result = tg_result.create_task(process_vuln(vuln_plugins,"plugins",row,username,doc_root,show_version))

            vuln, vuln_core_wp, vuln_dict = core_result.result()
            vuln, vuln_themes, vuln_dict = theme_result.result()
            vuln, vuln_plugins, vuln_dict = plugin_result.result()

        else:
            vuln_core_wp_status = await wp_vuln_core_wp_scanning(username, doc_root)
            vuln_themes = await wp_vuln_theme_scanning(username, doc_root, show_version=show_version, show_status=show_status)
            vuln_plugins = await wp_vuln_plugin_scanning(username, doc_root, show_version=show_version, show_status=show_status)

            vuln, vuln_core_wp, vuln_dict = await process_vuln(vuln_core_wp_status,"core",row,username,doc_root,show_version)
            vuln, vuln_themes, vuln_dict = await process_vuln(vuln_themes,"themes",row,username,doc_root,show_version)
            vuln, vuln_plugins, vuln_dict = await process_vuln(vuln_plugins,"plugins",row,username,doc_root,show_version)


        timestamp_now = datetime.now().timestamp()
        vuln_dict = await validate_wp_vuln(
            domain = domain,
            timestamp_now = timestamp_now,
            combined_modifying_date = combined_modifying_date,
            vuln = vuln,
            vuln_dict = vuln_dict,
            vuln_core_wp = vuln_core_wp,
            vuln_plugins = vuln_plugins,
            vuln_themes = vuln_themes,
            connection = connection
        )

        return vuln_dict
    
    except asyncio.CancelledError:
        logger.info("Vulnerability scan was cancelled. Shutting down...")
        raise

# coroutines for getting current modifying date
async def get_current_modifying_date(doc_root):
    """ Get the current modifying date. """

    logger = logging.getLogger("get_current_modifying_date")

    try:                
        if not os.path.exists(f"{doc_root}/wp-includes") or not os.path.exists(f"{doc_root}/wp-content/plugins") or not os.path.exists(f"{doc_root}/wp-content/themes"):
            return None
        
        directories = [f"{doc_root}/wp-includes", f"{doc_root}/wp-content/plugins", f"{doc_root}/wp-content/themes"]
        modifying_date_dict= {dir_name: os.stat(dir_name).st_mtime for dir_name in directories}
        biggest_modifying_date_key  = max(modifying_date_dict,key=modifying_date_dict.get)
        
        return modifying_date_dict[biggest_modifying_date_key]
    except OSError as e:
        logger.exception(f"Error in checking os stat for finding current modifying timestamp: {e}")

# coroutines for processing task
async def process_task(domain, since, config_dict,show_version=False,show_status=False, delta_time=18000, scan_concurrent=False):
    """Process the task."""



    logger = logging.getLogger("process_task")

    if not os.path.exists(VULN_WP_DB):
        success = await create_vuln_wp_database()
        if not success:
            logger.error("Failed to create database.")
            return

    try:
        async for rows in get_data_incident_im360(domain, since):
            for row in rows:
                    if row:
                        # print(row)
                        domain, username = await get_domain_username(row)
                        #if domain and username:
                        #    print(f"Domain: {domain}, Username: {username}")
                        doc_root = await get_document_root(domain)
                        #if doc_root:
                        #    print(f"Document Root: {doc_root}")

                        if username:
                            await install_wp_vuln_scanner(username, doc_root)

                        try:
                            async with aiosqlite.connect(VULN_WP_DB) as wp_vuln_db:
                                args = (domain,)
                                async with wp_vuln_db.execute(
                                    """
                                    SELECT modifying_date FROM vuln_wp_status WHERE domain=? ORDER BY timestamp

                                    """,
                                    args,
                                ) as cursor:
                                    list_modifying_date = await cursor.fetchall()
                                    current_modifying_date = await get_current_modifying_date(doc_root)
                                    if list_modifying_date:
                                        last_modifying_date = list_modifying_date[-1][0]
                                        if current_modifying_date > last_modifying_date:
                                            vuln_dict = await full_vuln_scan(
                                                    username = username,
                                                    domain = domain,
                                                    doc_root = doc_root,
                                                    row = row,
                                                    combined_modifying_date = current_modifying_date,
                                                    connection = wp_vuln_db,
                                                    show_version = show_version,
                                                    show_status = show_status,
                                                    scan_concurrent = scan_concurrent
                                            )
                                        else:
                                            logger.info("Check vuln from vuln_wp.db")
                                            async with wp_vuln_db.execute("""
                                            SELECT domain,timestamp,core_wp_vuln,themes_vuln,plugins_vuln FROM vuln_wp_status WHERE domain=? ORDER BY timestamp
                                            """,
                                            (domain,)) as cursor:
                                                result = await cursor.fetchall()
                                                incident_desc = row[2]
                                                vuln_dict = await check_vuln_from_wp_db(
                                                    username = username,
                                                    doc_root = doc_root,
                                                    incident_desc = incident_desc,
                                                    result = result,
                                                    show_version = show_version
                                                )

                                    else:
                                        vuln_dict = await full_vuln_scan(
                                                username = username,
                                                domain = domain,
                                                doc_root = doc_root,
                                                row = row,
                                                combined_modifying_date = current_modifying_date,
                                                connection = wp_vuln_db,
                                                show_version = show_version,
                                                show_status = show_status,
                                                scan_concurrent = scan_concurrent
                                        )

                                if vuln_dict:
                                    SLACK_CHANNEL = config_dict.get('config').get('notification').get('SLACK_CHANNEL')
                                    WEBHOOKS_URL = config_dict.get('config').get('notification').get('SLACK_WEBHOOKS_URL')

                                    if SLACK_CHANNEL and WEBHOOKS_URL:
                                        async with wp_vuln_db.execute(
                                            "SELECT notification_sended_time FROM vuln_wp_status WHERE domain=?",
                                            (domain,)
                                        ) as notification_time:
                                            notification_time = await notification_time.fetchall()
                                            last_notification_time = notification_time[-1][0] if notification_time else None
                                            cur_timestamp = datetime.now().timestamp()

                                            message = {
                                                    "domain": domain,
                                                    "data": [
                                                        vuln_dict
                                                    ],
                                            }
                                            if last_notification_time:

                                                delta_notification_time = cur_timestamp - last_notification_time

                                                if delta_notification_time:
                                                    #notification_time_delta_hours = ( delta_notification_time )
                                                    
                                                    if str(delta_time).endswith("h"):
                                                        delta_time = int(delta_time[:-1])
                                                        delta_time = delta_time*3600
                                                    elif str(delta_time).endswith("m"):
                                                        delta_time = int(delta_time[:-1])
                                                        delta_time = delta_time*60
                                                    elif str(delta_time).endswith('s'):
                                                        delta_time = int(delta_time[:-1])
                                                    else:
                                                        delta_time = delta_time

                                                    #if notification_time_delta_hours >= delta_time:
                                                    if delta_notification_time >= delta_time:
                                                        # fill this line with send_slack_message function call
                                                        # send_slack_message(WEBHOOKS_URL, SLACK_CHANNEL, vuln_dict)
                                                        logger.info("Send Slack Message")
                                                        await wp_vuln_db.execute(
                                                            """
                                                            UPDATE vuln_wp_status SET notification_sended_time=? WHERE domain=?
                                                            """,
                                                            (cur_timestamp, domain)
                                                        )
                                                        await wp_vuln_db.commit()

                                                        await slack_webhook(WEBHOOKS_URL, SLACK_CHANNEL, message)
                                            else:
                                                logger.info("Notification time is empty, udpate it at db then send notification")
                                                await wp_vuln_db.execute(
                                                    "UPDATE vuln_wp_status SET notification_sended_time=? WHERE domain=?",
                                                    (
                                                        cur_timestamp,
                                                        domain,
                                                    ),
                                                )
                                                await wp_vuln_db.commit()
                                                await slack_webhook(WEBHOOKS_URL, SLACK_CHANNEL, message)

                        except asyncio.CancelledError:
                            logger.info("Task was cancelled. Shutting down...")
                            raise
                        except aiosqlite.Error as e:
                            logger.exception(f"An error occurred: {e}")
    except asyncio.CancelledError:
        logger.info("Task was cancelled. Shutting down...")
        raise

# coroutines main
async def main():
    domain = ""
    args = setArgument()
    delta_time = 5

    sleep_time = 3
    max_sleep_time = 5
    base_sleep_time = 3

    config_file = sanitize_filepath(CONFIG_FILE)

    if not os.path.exists(config_file):
        print(f"Warning: {CONFIG_FILE} not found. Add your configuration in .config file first!")
        return

    with open(config_file, "r") as f:
        config_dict = yaml.safe_load(f)
        config_dict = await verify_config(config_dict)


        logging_dict = config_dict.get("config").get("logging")

        if config_dict.get("config").get("notification").get("SHOW_VERSION"):
            show_version = config_dict.get("config").get("notification").get("SHOW_VERSION")
        
        if config_dict.get("config").get("notification").get("SHOW_STATUS"):
            show_status = config_dict.get("config").get("notification").get("SHOW_STATUS")
        
        if config_dict.get("config").get("notification").get("DELTA_TIME"):
            delta_time = config_dict.get("config").get("notification").get("DELTA_TIME")

        if task_config := config_dict.get("config").get("task"):
            if task_config.get("scan_concurrent"):
                scan_concurrent = task_config.get("scan_concurrent")
        # print(f"Logging dict: {logging_dict}")

        if logging_dict:
            # print(f"Logging dict: {logging_dict}")
            await config_logging(logging_dict)
        else:
            print(f"Warning: {CONFIG_FILE} does not contain logging configuration.")
            sys.exit(1)

    logger = logging.getLogger("main")

    # logger.info("test log")
    
    if args and args.domain:
        domain = args.domain.replace("www.", "")
    
    since = args.since
    sleep_time = 5  # Start with 5 seconds sleep time

    if not os.path.exists(VULN_WP_DB):
        success = await create_vuln_wp_database()
        await asyncio.sleep(2)
        if not success:
            logger.error("Failed to create database.")
            return
    try:
        while True:
            task_available = await check_for_tasks()
            
            if task_available:
                logger.info("Task available, processing...")
                # prepare positional arguments
                pos_args = [domain, since, config_dict]
                # prepare keywords arguments
                kwargs = {}

                if 'show_version' in locals():
                    if show_version:
                        kwargs["show_version"] = show_version
                if 'show_status' in locals():
                    if show_status:
                        kwargs["show_status"] = show_status
                if 'delta_time' in locals():
                    if delta_time:
                        kwargs["delta_time"] = delta_time
                
                if 'scan_concurrent' in locals():
                    if scan_concurrent:
                        kwargs["scan_concurrent"] = scan_concurrent

                await process_task(*pos_args, **kwargs)
                sleep_time = base_sleep_time  # Reset sleep time after processing a task
            else:
                logger.info(f"No task available, waiting for {sleep_time} seconds...")
                await asyncio.sleep(sleep_time)
                # Implement sum + 1 backoff, up to 5 seconds

                sleep_time = min(sleep_time + 1, max_sleep_time)
    except asyncio.CancelledError:
        logger.info("Main loop was cancelled. Shutting down...")
    finally:
        logger.info("Shutdown complete.")

# define main
if __name__ == "__main__":
    asyncio.run(main())