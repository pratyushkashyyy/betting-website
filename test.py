import os
from twilio.rest import Client

# Find your Account SID and Auth Token at twilio.com/console
# and set the environment variables. See http://twil.io/secure

client = Client('ACb0a62a64b64ac6a9f1f926b3512dcc86', '0754529c6f76435a2b5b43278d16d2ea')

message = client.messages.create(
                        body='This is the ship that made the Kessel Run in fourteen parsecs?',
                        from_='+18144580408',
                        to='+918406909448'
                     )

print(message.sid)
