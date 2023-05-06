import tomllib
import logging
from logging import handlers
import sys
import datetime
import json
from collections import namedtuple
import socket
import ssl
import threading
import random
import re
import time
import json
import http.client
import urllib.parse

try:
	import curses
	from curses import wrapper
	has_curses = True
except:
	has_curses = False


class logclient(logging.getLoggerClass()):
	def __init__(self, name, channel):
		super().__init__(name)
		self.setLevel(logging.DEBUG)
		self.stdout_handler = logging.StreamHandler(sys.stdout)
		self.stdout_handler.setLevel(logging.INFO)
		self.stdout_handler.setFormatter(
			logging.Formatter(
				'%(asctime)s | %(levelname)-8s | %(message)s',
				datefmt="%I:%M:%S %p"
		))
		self.addHandler(self.stdout_handler)

		now = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
		self.log_file = f"logs/irc_log_{channel}_{now}.log"
		self.file_handler = logging.handlers.RotatingFileHandler(self.log_file, mode='w', backupCount=5)
		self.file_handler.setLevel(logging.DEBUG)
		self.file_handler.setFormatter(
			logging.Formatter(
				'%(asctime)s | %(levelname)-8s | %(message)s',
				datefmt="%m/%d/%Y %H:%M:%S"
		))
		self.addHandler(self.file_handler)


class authclient:
	def AquireToken(client_id, client_secret, code):
		headers = {
			'Content-Type': 'application/x-www-form-urlencoded'
		}
		params = {
			'client_id': client_id,
			'client_secret': client_secret,
			'code': code,
			'grant_type': 'authorization_code',
			'redirect_uri': 'http://localhost'
		}
		params = urllib.parse.urlencode(params)
		
		connection = http.client.HTTPSConnection("id.twitch.tv")
		connection.request("POST", "/oauth2/token", headers=headers, body=params)
		response = connection.getresponse()
		t = time.time()
		
		success = False
		if response.status == 200:
			success = True

		data = response.read()
		connection.close()
		return success, data, int(t)

	def ValidateToken(token):
		headers = {
			'Authorization': f'OAuth {token}'
		}
		
		connection = http.client.HTTPSConnection("id.twitch.tv")
		connection.request("GET", "/oauth2/validate", headers=headers)
		response = connection.getresponse()

		valid = False
		if response.status == 200:
			valid = True

		data = response.read()
		connection.close()
		return valid, data

	def RefreshToken(token, client_id, client_secret):
		headers = {
			'Content-Type': 'application/x-www-form-urlencoded'
		}
		params = {
			'client_id': client_id,
			'client_secret': client_secret,
			'grant_type': 'refresh_token',
			'refresh_token': token
		}
		params = urllib.parse.urlencode(params)
		
		connection = http.client.HTTPSConnection("id.twitch.tv")
		connection.request("POST", "/oauth2/token", headers=headers, body=params)
		response = connection.getresponse()
		t = time.time()
		
		success = False
		if response.status == 200:
			success = True

		data = response.read()
		connection.close()
		return success, data, int(t)

	def ValidateSchema(json_token, logger):
		schema = {
			"access_token":"",
			"refresh_token":"",
			"scope":"",
			"token_type":"",
			"expires_in":0,
			"obtained":0
		}

		if json_token:
			for key in schema:
				if key not in json_token:
					logger.warning(f'JSON oauth token invalid. | {json_token}')
					return False
		return True

	def WriteToken(str, obtained):
		data = json.loads(str)
		auth_token = {
			"access_token":data['access_token'],
			"refresh_token":data['refresh_token'],
			"scope":data['scope'],
			"token_type":data['token_type'],
			"expires_in":data['expires_in'],
			"obtained": obtained
		}

		with open('auth.json', 'w') as file:
			json.dump(auth_token, file)

		return auth_token


# Twitch IRC message structure
Message = namedtuple(
	'Message',
	'tags prefix user channel irc_command irc_args text text_command text_args'
)


class twitchbot:
	def __init__(self, config, auth_token, logger):
		# Twitch IRC server
		self.irc_server = "irc.chat.twitch.tv"
		self.irc_port = 6697
		self.rate_limit = 30/100
		self.last_sent_msg = time.monotonic()
		self.last_ping_msg = time.monotonic()

		# Load authentication config		
		self.nick = config['nick']
		#self.oauth_token = config['oauth_token'] # old config.toml token
		self.oauth_token = auth_token
		self.channel = config['channel']
		self.command_char = config['command_char']

		# Create logger
		self.logger = logger
		self.logger.info("Loaded config...")

		self.state = {}
		self.state_file = 'config.json'
		self.state_schema = {
			'template_commands': {},
			'counters': {},
			'chat_timers': {},
			'mods': [],
			'greetings': [],
		}

	def init(self):
		self.load_state()
		self.logger.debug(self.state)

		self.mod_commands = {
			'byebot': self.disconnect,
			'addcmd': self.add_template_command,
			'modcmd': self.edit_template_command,
			'delcmd': self.delete_template_command,
			'addcounter': self.add_counter,
			'modcounter': self.edit_counter,
			'delcounter': self.delete_counter,
		}
		self.custom_commands = {
			'cmds': self.list_commands,
		}

		self.connected = False
		self.connect_to_twitch()

	def check_schema(self):
		is_dirty = False
		for key in self.state_schema:
			if key not in self.state:
				is_dirty = True
				self.state[key] = self.state_schema[key]
		return is_dirty

	def load_state(self):
		try:
			with open(self.state_file, 'r') as file:
				self.state = json.load(file)
			self.logger.info(f"Loaded state...")
		except Exception as e:
			self.logger.warning(f"Error loading state | {e}")

		is_dirty = self.check_schema()
		if is_dirty:
			self.logger.warning(f"Dirty state... writing to disk...")
			self.save_state()

	def save_state(self):
		try:
			with open(self.state_file, 'w') as file:
				json.dump(self.state, file, indent=4)
			self.logger.info(f"State saved to {self.state_file}")
		except Exception as e:
			self.logger.error(f"Unable to save state to {self.state_file} | {e}")
			return False

		return True

	def connect_to_twitch(self):
		self.logger.info(f"Connecting to Twitch IRC server...")
		try:
			ssl_context = ssl.create_default_context()
			self.irc_socket = ssl_context.wrap_socket(
				socket.create_connection((self.irc_server, self.irc_port)),
				server_hostname=self.irc_server
			)
			self.listen = True
			self.connected = True
			self.logger.info(f"Connected to {self.irc_server}:{self.irc_port}")
		except Exception as e:
			self.logger.critical(f"Failed to connect to {self.irc_server}:{self.irc_port} | {e}")
			return

		try:
			self.listener = threading.Thread(target=self.process_irc_messages)
			self.listener.start()
			self.logger.info(f"Started listener")

			self.timer = threading.Thread(target=self.process_timers)
			self.timer.start()
			self.logger.info(f"Started timer")

			ct = time.monotonic()
			for key in self.state['chat_timers']:
				timer = self.state['chat_timers'][key]
				if ct - timer[0] > timer[1]:
					timer[0] = ct
		except Exception as e:
			self.logger.critical(f"Failed to start process loops | {e}")
			self.irc_socket.close()
			return

		self.logger.info(f"Authenticating...")
		self.send_irc_command(f'PASS oauth:{self.oauth_token}')
		self.send_irc_command(f'NICK {self.nick}')
		self.send_irc_command(f'CAP REQ :twitch.tv/commands twitch.tv/membership twitch.tv/tags')

		self.send_irc_command(f'JOIN #{self.channel}')
		greeting = self.state['greetings'][random.randrange(0, len(self.state['greetings']))]
		self.send_privmsg(f"{greeting}")

	def disconnect(self, message):
		self.send_privmsg("I've been a good bot!")
		self.send_irc_command(f"PART #{self.channel}")
		self.listen = False
		self.irc_socket.close()

	def parse_message(self, msg):
		parts = msg.split(' ')
		tags = None
		prefix = None
		user = None
		channel = None
		text = None
		text_command = None
		text_args = None
		irc_command = None
		irc_args = None

		def get_prefix_user(prefix):
			domain = prefix.split('!')[0]

			if 'tmi.twitch.tv' not in domain:
				return domain
			if domain.endswith('.tmi.twitch.tv'):
				return domain.replace('.tmi.twitch.tv', '')
			return None

		# get twitch tags
		if parts[0].startswith('@'):
			tags = parts[0][1:]
			parts = parts[1:]

		# get prefix and user
		if parts[0].startswith(':'):
			prefix = parts[0][1:]
			user = get_prefix_user(prefix)
			if user is None:
				user = parts[2]	
			parts = parts[1:]

		# get text
		text_start = next(
			(i for i, part in enumerate(parts) if part.startswith(':')),
			None
		)
		if text_start is not None:
			text_parts = parts[text_start:]
			text_parts[0] = text_parts[0][1:]
			text = ' '.join(text_parts)

			# check to see if we received a chat command
			if (text_parts[0].startswith(self.command_char)):
				text_command = text_parts[0][len(self.command_char):]
				text_args = text_parts[1:]
				for i, arg in enumerate(text_args):
					if arg.startswith('@'):
						text_args[i] = text_args[i].replace('@', '')
			parts = parts[:text_start]

		# get IRC stuff
		irc_command = parts[0]
		irc_args = parts[1:]

		# get channel
		channel_start = next(
			(i for i, part in enumerate(irc_args) if part.startswith('#')),
			None
		)
		if channel_start is not None:
			channel = irc_args[channel_start][1:]

		message = Message(
			tags = tags,
			prefix = prefix,
			user = user,
			channel = channel,
			text = text,
			text_command = text_command,
			text_args = text_args,
			irc_command = irc_command,
			irc_args = irc_args,
		)
		return message

	# Functions as the main bot loop to receive messages
	def process_irc_messages(self):
		while self.listen:
			received_msgs = self.irc_socket.recv(2048).decode()
			for rmsg in received_msgs.split('\r\n'):
				self.handle_irc_message(rmsg)

			ct = time.monotonic()
			if ct - self.last_ping_msg > 600:
				self.logger.warning(f"Last received ping {int(dt)} ago: Connection dead")

	def process_timers(self):
		while self.listen:
			ct = time.monotonic()
			for key in self.state['chat_timers']:
				timer = self.state['chat_timers'][key]
				if ct - timer[0] > timer[1]:
					self.send_privmsg(f"{timer[2]}")
					timer[0] = ct


	def handle_irc_message(self, rmsg):
		if len(rmsg) == 0:
			return

		message = self.parse_message(rmsg)
		self.logger.info(f'>>> {rmsg}')
		#self.logger.info(f'>>> {message}')

		if message.irc_command == 'NOTICE *':
			self.logger.error(f'>>> {rmsg}')

		elif message.irc_command == 'CAP * NACK':
		 	self.logger.error(f'>>> {rmsg}')

		elif message.irc_command == 'CAP * ACK':
		 	self.logger.info(f' >>> {rmsg}')

		elif message.irc_command == 'PING':
			self.last_ping_msg = time.monotonic()
			self.send_irc_command('PONG :tmi.twitch.tv')

		elif message.irc_command == 'PRIVMSG':
			if message.text_command in self.custom_commands:
				self.logger.info(f'Received command: {message.text_command}')
				self.custom_commands[message.text_command](message)

			elif message.user in self.state['mods'] and message.text_command in self.mod_commands:
				self.logger.info(f'Received command: {message.text_command}')
				self.mod_commands[message.text_command](message)

			elif message.text_command in self.state['template_commands']:
				self.logger.info(f'Received command: {message.text_command}')
				self.handle_chat_command(
					message, 
					message.text_command, 
					self.state['template_commands'][message.text_command]
				)

	def send_irc_command(self, command):
		while True:
			dt = time.monotonic() - self.last_sent_msg
			if dt > self.rate_limit:
				self.irc_socket.send(
					(f'{command}\r\n').encode()
				)
				self.last_sent_msg = time.monotonic()
				break

		if 'PASS' not in command:
			self.logger.info(f'<<< {command} | {dt}')

	def send_privmsg(self, text):
		self.send_irc_command(f'PRIVMSG #{self.channel} :{text}')
	
	def handle_chat_command(self, message, command, template)	:
		try:
			text = template.format(**{'message': message, 'self': self})
		except IndexError:
			text = f'@{message.user} Your command is missing arguments.'
		except Exception as e:
			text = f'@{message.user} Something went wrong.'
			self.logger.warning(f'Error running command: {command} | {template} | {e} | {message}')

		self.send_privmsg(text)


	# Custom command functions
	def add_template_command(self, message, force=False):
		if len(message.text_args) < 2:
			text = f"@{message.user} Need <cmd name> <template> as arguments."
			self.send_privmsg(text)
			self.logger.warning(f'Could not add new command: not enough arguments')
			return

		command = re.sub(r'[^a-z]+', '', message.text_args[0].lower())
		template = ' '.join(message.text_args[1:])

		if command in self.custom_commands:
			text = f'@{message.user} Command {command} already exists and cannot be replaced.'
			self.send_privmsg(text)
			self.logger.warning(f"{command} already exists in custom_commands")
			return

		if command in self.state['template_commands'] and not force:
			text = f'@{message.user} Command {command} already exists. Use {self.command_char}modcmd to modify.'
			self.send_privmsg(text)
			self.logger.warning(f"{command} already exists in template_commands")
			return

		self.state['template_commands'][command] = template
		if self.save_state():
			text = f'@{message.user} {command}'
			text += ' added.' if not force else ' modified.'
		else:
			text = f'@{message.user} {command} not saved.'
		self.send_privmsg(text)

	def edit_template_command(self, message):
		return self.add_template_command(message, force=True)

	def delete_template_command(self, message):
		if len(message.text_args) < 1:
			text = f"@{message.user} Need <cmd name> as argument."
			self.send_privmsg(text)
			self.logger.warning(f'Could not remove command: not enough arguments')
			return

		command = message.text_args[0]
		del self.state['template_commands'][command]
		if self.save_state():
			text = f'@{message.user} {command} removed.'
		else:
			text = f'@{message.user} {command} removal not saved.'
		self.send_privmsg(text)

	def list_commands(self, message):
		commands = list(self.custom_commands.keys())
		commands += list(self.state['template_commands'].keys())
		if message.user in self.state['mods']:
			commands += list(self.mod_commands.keys())

		commands = [self.command_char + cmd for cmd in commands]
		text = f"@{message.user} {' '.join(commands)}"
		self.send_privmsg(text)

	def add_counter(self, message, force=False):
		if len(message.text_args) < 2:
			text = f"@{message.user} Need <counter name> <start count> as arguments."
			self.send_privmsg(text)
			self.logger.warning(f'Could not add new counter: not enough arguments')
			return

		counter = message.text_args[0]
		try:
			count = int(message.text_args[1])
		except:
			text = f'@{message.user} Stat count must be a number.'
			self.send_privmsg(text)
			self.logger.warning(f'Could not add new counter')
			return

		if counter in self.state['counters'].keys() and not force:
			text = f'@{message.user} Counter {counter} already exists. Use {self.command_char}modcounter to modify.'
			self.send_privmsg(text)
			self.logger.warning(f"{counter} already exists in counters")
			return
			
		self.state['counters'][counter] = count
		if self.save_state():
			text = f'@{message.user} {counter}'
			text += ' added.' if not force else ' modified.'
		else:
			text = f'@{message.user} {counter} not saved.'
		self.send_privmsg(text)

	def edit_counter(self, message):
		return self.add_counter(message, force=True)

	def delete_counter(self, message):
		if len(message.text_args) < 1:
			text = f"@{message.user} Need <counter name> as argument."
			self.send_privmsg(text)
			self.logger.warning(f'Could not remove counter: not enough arguments')
			return

		counter = message.text_args[0]
		del self.state['counters'][counter]
		if self.save_state():
			text = f'@{message.user} {counter} removed.'
		else:
			text = f'@{message.user} {counter} removal not saved.'
		self.send_privmsg(text)


def main():	
	logger = logclient(__name__, 'reyyn')

	# Load configuration
	config = None
	try:
		with open('config.toml' ,'rb') as configfile:
			config = tomllib.load(configfile)['Auth']
	except Exception as e:
		logger.error(f"Could not load config file | {e}")
		return

	# Load auth token
	token = None
	try:
		with open('auth.json', 'r') as file:
			token = json.load(file)
	except Exception as e:
		logger.warning(f"Could not load auth token. | {e}")

	good_token = False
	if token:
		logger.info(f'Validating auth token...')
		good_token = authclient.ValidateSchema(token, logger)

	# If we need a new token
	if not good_token or not token:
		logger.warning(f'Bad/missing auth token. Fetching new token...')
		print("Need a new authorization code. Navigate to: ")
		print("https://id.twitch.tv/oauth2/authorize?response_type=code&client_id=9lk1kx0z0e7wb2nvaxbtllol58ou79&redirect_uri=http://localhost&scope=chat%3Aread+chat%3Aedit+channel%3Amoderate+whispers%3Aread+whispers%3Aedit&state=d0f9g8n0mnnokoj7kln2hbv45l6")
		print('\n Copy the code from this portion or your URL: http://localhost/?code=xxxxxYOUR CODE IS HERExxxxx')
		code = input('\n Enter that code here: ')
		sucess, web_token, time_obtained = authclient.AquireToken(config['client_id'], config['client_secret'], code)
		if success:
			logger.info(f'New auth token obtained... Saving...')
			token = authclient.WriteToken(web_token, time_obtained)
		else:
			logger.error(f'Could not obtain new auth token. | {web_token}')

	# Check that token isn't expired
	current_time = int(time.time())
	dt = current_time - token['obtained']
	if dt > token['expires_in']:
		logger.warning(f'Auth token expired... Refreshing token...')
		success, web_token, time_obtained = authclient.RefreshToken(token['refresh_token'], config['client_id'], config['client_secret'])
		if success:
			logger.info(f'Auth token refreshed... Saving...')
			token = authclient.WriteToken(web_token, time_obtained)
		else:
			logger.error(f'Could not refresh auth token. | {web_token}')
			return

	# final check that we do have a token
	if not token:
		logger.critical(f'Token is Hudini')

	bot = twitchbot(config, token['access_token'], logger)
	bot.init()


if __name__ == '__main__':
	main()
	