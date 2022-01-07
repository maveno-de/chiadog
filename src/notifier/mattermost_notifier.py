# std
import json
import http.client, ssl
from base64 import b64encode
import logging
import urllib.parse
from typing import List

# project
from . import Notifier, Event
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
                sslContext = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                sslContext.load_verify_locations('/etc/ssl/certs/ca-certificates.crt')
                conn = http.client.HTTPSConnection(o.netloc, timeout=self._conn_timeout_seconds, context=sslContext)
                message = {"text": f"**{self.get_title_for_event(event)}**\n{event.message}"}
                conn.request(
                    "POST",
                    o.path,
                    json.dumps(message).encode('utf8'),
                    {"Content-type": "application/json",
                     "Authorization": 'Basic %s' % base64UsernamePassword }
                )
                response = conn.getresponse()
                if response.getcode() != 200:
                    logging.warning(f"Problem sending event to user, code: {response.getcode()}")
                    errors = True
                conn.close()

        return not errors
