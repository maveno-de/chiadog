# std
import json
import http.client
from base64 import b64encode
import logging
import urllib.parse
from typing import List

# project
from . import Notifier, Event

# channel_id: 'dummy_channel_id'
# username: 'dummy_username'
# password: 'dummy_password'
# host: 'dummy_hostname'

class MattermostNotifier(Notifier):
    def __init__(self, title_prefix: str, config: dict):
        logging.info("Initializing Mattermost notifier.")
        super().__init__(title_prefix, config)
        try:
            credentials = config["credentials"]

            self.webhook_url = f"https://{ credentials['host'] }/hooks/{ credentials['channel_id'] }"
        except KeyError as key:
            logging.error(f"Invalid config.yaml. Missing key: {key}")

    def send_events_to_user(self, events: List[Event]) -> bool:
        errors = False
        for event in events:
            if event.type in self._notification_types and event.service in self._notification_services:

                o = urllib.parse.urlparse(self.webhook_url)

                usernamePassword = f"credentials['username']:credentials['password']".encode('utf-8')
                base64UsernamePassword = b64encode(usernamePassword).decode("ascii")
                usernamePasswordHeaders = { 'Authorization' : 'Basic %s' %  base64UsernamePassword }

                conn = http.client.HTTPSConnection(o.netloc, timeout=self._conn_timeout_seconds, headers=usernamePasswordHeaders)

                message = {"text": f"**{self.get_title_for_event(event)}**\n{event.message}"}
                conn.request(
                    "POST",
                    o.path,
                    urllib.parse.urlencode(
                        {
                            "content": json.dumps(message).encode('utf8')
                        }
                    ),
                    {"Content-type": "application/json"},
                )
                response = conn.getresponse()
                if response.getcode() != 204:
                    logging.warning(f"Problem sending event to user, code: {response.getcode()}")
                    errors = True
                conn.close()

        return not errors
