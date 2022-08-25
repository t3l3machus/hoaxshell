import cryptography.hazmat.primitives.asymmetric.rsa
import datetime

def generate_private_key():
	#Generate Key with "cryptography" (https://pypi.org/project/cryptography/)
	#Using full package paths for clarity.  This can be reduced with additional imports above.
	key = cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(
		public_exponent=65537,
		key_size=2048,
		)
	#Write to a file in the local directory.
	key_filename = "default_hoaxshell.pem"

	with open(key_filename,"wb") as f:
		f.write(key.private_bytes(
			encoding = cryptography.hazmat.primitives.serialization.Encoding.PEM,
			format = cryptography.hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL,
			#Using NoEncryption here for a default key, but this can be changed to BestAvailableEncryption(b"password") if needed
			encryption_algorithm = cryptography.hazmat.primitives.serialization.NoEncryption(),
			))
	return key,key_filename

def generate_cert_from_key(key,certname="default_hoaxshell.crt"):
	#Generate self-signed cert
	#Custom serial for IOC purposes
	serial = int('40ac5431140ac5431140ac5431140ac5431140a',16)

	#Get current time
	iss_time = datetime.datetime.now()

	#Explicitly define name for IOC purposes
	subject = cryptography.x509.Name([
		cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.COUNTRY_NAME,u'US'),
		cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.STATE_OR_PROVINCE_NAME,u'Texas'),
		cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.LOCALITY_NAME,u'Nowhere'),
		cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.ORGANIZATION_NAME,u'default_hoaxshell'),
		cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME,u'default_hoaxshell'),
		cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.COMMON_NAME,u'default_hoaxshell'),
		])
	issuer = cryptography.x509.Name([
		cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.COUNTRY_NAME,u'US'),
		cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.ORGANIZATION_NAME,u'default_hoaxshell'),
		cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.COMMON_NAME,u'default_hoaxshell'),
		])
	cert = cryptography.x509.CertificateBuilder().subject_name(subject
		).issuer_name(
			issuer
		).public_key(
			key.public_key()
		).serial_number(
			serial
		).not_valid_before(
			iss_time
		).not_valid_after(
			iss_time + datetime.timedelta(days=365)
		).add_extension(
			cryptography.x509.CRLDistributionPoints([
				cryptography.x509.DistributionPoint(
					full_name=[
						#Shout out to the Github Repo
						cryptography.x509.UniformResourceIdentifier(u'https://github.com/t3l3machus/hoaxshell'),
						cryptography.x509.UniformResourceIdentifier(u'https://github.com/t3l3machus/hoaxshell')
					],
					relative_name=None,
					crl_issuer=None,
					reasons=None
					),
			]),
			critical=False
		#Finally (self-)sign the certificate
		).sign(key,cryptography.hazmat.primitives.hashes.SHA256())

	#Write certificate to file in local directory
	with open(f'{certname}','wb') as f:
		f.write(cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM))
	return certname

def generate():
	#Generate the key object and file
	key,key_filename = generate_private_key()
	#Generate the cert object and file
	cert_filename = generate_cert_from_key(key)
	return key_filename,cert_filename

if __name__ == '__main__':
	pass
