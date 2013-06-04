from __future__ import print_function
import socket
import ssl
import OpenSSL
import pprint
import urllib2
import popen2
import string
import re
import MySQLdb
from Crypto.Util import asn1
import hashlib
import csv
import base64
import sys
from threading import Thread
from Queue import Queue, Empty
import time
import thread
import multiprocessing


########################################################
# 	This is for non-blocking reading from the PIPE #
########################################################

def enqueue_output(out, queue):
	for line in iter(out.readline, b''):
		queue.put(line)
	out.close()
	pass

########################################################
# 	Processing the URLs			       #
########################################################

########################################################
# 	Prepare the DB connection		       #
########################################################

# Open database connection
db = MySQLdb.connect("localhost","root","","CRL" )

# prepare a cursor object using cursor() method
cursor = db.cursor()

########################################################
#	Getting the Certificates	               #	
########################################################

L = list()
L.append("zavers.com")
	
for x in L:
	
	#print ("Connecting to %s" % csvrow[1])
	#print ("Connecting to %s" % x)

	##### Make sure the connection valid with aggressive timeout #####
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
	s.settimeout(4);

	try:
		#s.connect((csvrow[1], 443));
		s.connect((x, 443));
	except socket.timeout:
		print ("Timeout connecting to [%s]" % x)
		s.close()
		continue
	except Exception:
		#print ("\tError [%s]" % sys.exc_info()[1])
		continue

	s.close();

	##### Holds all the certificates in the chain #####

	certs = list()

	###############################################################
	##### Running the openssl command to get the certificates #####

	#fin, fout, ferr = popen2.popen3("GET | openssl s_client -connect %s:443 -showcerts" % csvrow[1])
	fin, fout, ferr = popen2.popen3("GET | openssl s_client -connect %s:443 -showcerts" % x)
	fout.write("GET\n\n")
	fout.close()
	ferr.close()
	
	qu = Queue()
	thr = Thread(target=enqueue_output, args=(fin, qu))
	thr.daemon = True
	thr.start()
	
	time.sleep(1)

	certFound = 0
	while True:

		try:
			line = qu.get_nowait()
		except Empty:
			break
		else:

			######################################
			##### Processing the certificate #####

			if (certFound == 1):
				cert += line

			matchObj = re.search( r'BEGIN CERTIFICATE', line, re.I|re.M)
			if matchObj:
				certFound = 1
				cert = line;

			matchObj = re.search( r'END CERTIFICATE', line, re.I|re.M)
			if matchObj:
				certFound = 0;
				certs.append(cert);

			#####################################
			##### Processing the connection #####

			matchObj = re.search( r'^.*Protocol\s*:\s*(.*)$', line, re.I|re.M)
			if matchObj:
				protocol = matchObj.group(1)

			matchObj = re.search( r'^.*Cipher\s*:\s*(.*)$', line, re.I|re.M)
			if matchObj:
				cipher = matchObj.group(1)

			##### End of Loop

	if len(certs) == 0:
		continue
	#######################################################
	##### Insert the connection information in the DB #####

	sql = '''INSERT INTO ssl_connec(protocol, cipher) VALUES ("%s", "%s");''' % (protocol, cipher)
	try:
		cursor.execute(sql)
		conn_id = db.insert_id()
		db.commit()
	except MySQLdb.Error, e:
		db.rollback()
		print ("\tError1 %d: %s" % (e.args[0], e.args[1]))
		print ("\tError1 saving the connection information to [%s] in the DB" % x)


	############################################
	##### Loop over the certs in the chain #####
	############################################

	for index, cert in enumerate(certs):
		x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

		#########################################
		##### Insert the issuer information #####

		issuer = x509.get_issuer()
		if issuer.organizationName != None:
			matchObj = re.search( r'^.*"(.*)".*$', issuer.organizationName, re.I|re.M)
			if matchObj:
				issuer.organizationName = matchObj.group(1)
		sql = '''INSERT INTO names(country, org, org_unit, com_name) VALUES ("%s", "%s", "%s", "%s");''' % (issuer.countryName, issuer.organizationName, issuer.organizationalUnitName, issuer.commonName)

		Issuer_id = -1
		try:
			cursor.execute(sql)
			issuer_id = db.insert_id()
			db.commit()
		except MySQLdb.Error, e:
			if e.args[0] == 1062:
				sql = '''SELECT name_id FROM names WHERE country="%s" AND org="%s" AND org_unit="%s" AND com_name="%s"''' % (issuer.countryName, issuer.organizationName, issuer.organizationalUnitName, issuer.commonName)
				cursor.execute(sql)
				issuer_id = cursor.fetchone()[0]
			else:
				db.rollback()
				print ("\tError2 %d: %s SQL STMT [%s]" % (e.args[0], e.args[1], sql))
				print ("\tError2 saving the issuer information in the DB in [%s]", x)
		

		##########################################	
		##### Insert the subject information #####

		subject = x509.get_subject()
		if subject.organizationName != None:
			matchObj = re.search( r'^.*"(.*)".*$', subject.organizationName, re.I|re.M)
			if matchObj:
				subject.organizationName = matchObj.group(1)
		sql = '''INSERT INTO names(country, org, org_unit, com_name) VALUES ("%s", "%s", "%s", "%s");''' % (subject.countryName, subject.organizationName, subject.organizationalUnitName, subject.commonName)

		subject_id = -1
		try:
			cursor.execute(sql)
			subject_id = db.insert_id()
			db.commit()
		except MySQLdb.Error, e:
			if e.args[0] == 1062:
				sql = '''SELECT name_id FROM names WHERE country="%s" AND org="%s" AND org_unit="%s" AND com_name="%s"''' % (subject.countryName, subject.organizationName, subject.organizationalUnitName, subject.commonName)
				cursor.execute(sql)
				subject_id = cursor.fetchone()[0]
			else:
				db.rollback()
				print ("\tError3 %d: %s" % (e.args[0], e.args[1]))
				print ("\tError3 saving the subject information in the DB in [%s] with SQL [%s]" % (x, sql))



		##############################
		##### Get the Extensions #####

		crl_uri = ""
		auth_uri = ""

		ext_count = x509.get_extension_count()
		for i in range (0, ext_count):
			x509_ext = x509.get_extension(i)
			ext_name = x509_ext.get_short_name()

			matchObj = re.search( r'^.*crlDistributionPoints.*$', ext_name, re.I|re.M)
			if matchObj:
				ext_data = x509_ext.get_data()
				matchObj = re.search( r'^.*(http:.*crl).*$', ext_data, re.I|re.M)
				try:
					crl_uri = matchObj.group(1)
				except:
					#print ("\tError3_1 error getting the CRL URI [%s] when connecting to [%s]" % (ext_data, x))
					pass

			matchObj = re.search( r'^.*authorityInfoAccess.*$', ext_name, re.I|re.M)
			if matchObj:
				ext_data = x509_ext.get_data()
				matchObj = re.search( r'^.*(http:.*)$', ext_data, re.I|re.M)
				try:
					auth_uri = matchObj.group(1)
				except:
					#print ("\tError3_2 error getting the Auth URI [%s] when connecting to [%s]" % (ext_data, x))
					pass
				
		

		##############################################
		##### Insert the Authority URI in the DB #####
		
		auth_id = -1
		if auth_uri != "":
			sql = '''INSERT INTO authority(auth_uri) VALUES ("%s")''' % auth_uri
			try:
				cursor.execute(sql)
				auth_id = db.insert_id()
				db.commit()
			except MySQLdb.Error, e:
				if e.args[0] == 1062:
					sql = '''SELECT auth_id FROM authority WHERE auth_uri="%s"''' % auth_uri
					cursor.execute(sql)
					auth_id = cursor.fetchone()[0]
				else:
					db.rollback()
					print ("\tError4 %d: %s" % (e.args[0], e.args[1]))
					print ("\tError4 saving the Authority information in the DB in [%s]", x)


		########################################
		##### Insert the CRL URI in the DB #####
		
		crl_uri_id = -1
		existing_uri = 0
		if crl_uri != "":
			sql = '''INSERT INTO crls_uri(crl_uri) VALUES ("%s")''' % crl_uri
			try:
				cursor.execute(sql)
				crl_uri_id = db.insert_id()
				db.commit()
			except MySQLdb.Error, e:
				if e.args[0] == 1062:
					existing_uri = 1
					sql = '''SELECT crl_uri_id FROM crls_uri WHERE crl_uri="%s"''' % crl_uri
					cursor.execute(sql)
					crl_uri_id = cursor.fetchone()[0]
				else:
					db.rollback()
					print ("\tError5 %d: %s SQL STMT [%s]" % (e.args[0], e.args[1], sql))
					print ("\tError5 saving the CRL URI [%s] in the DB in [%s]" % (crl_uri, x))
	

		#################################################
		##### Getting the CRL Object and parsing it #####
		
		if crl_uri != "":
			try:
				res = urllib2.urlopen(crl_uri)
				crl_der = res.read()
				digest = hashlib.sha256()
				digest.update(crl_der)
				crl_digest = digest.digest()
				crl_size = len(crl_der)
				crl = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, crl_der)
				revoked = crl.get_revoked()
				if revoked != None:
					num_of_revoked = len(revoked)
				crl_id = -1
				updated_crl = 0
				if existing_uri == 1:
					sql = '''SELECT COUNT(*) FROM crls WHERE crl_digest="%s"''' % base64.b64encode(crl_digest)
					try:
						cursor.execute(sql)
						if cursor.fetchone()[0] == 0:
							updated_crl = 1
						#else:
							#print ("\tThe CRL [%s] is already in the DB" % crl_uri)
					except MySQLdb.Error, e:
						db.rollback()
						print ("\tError6 %d: %s" % (e.args[0], e.args[1]))
						
				if existing_uri == 0 or updated_crl == 1:
					sql = '''INSERT INTO crls(crl_uri_id, num_of_revoked, crl_size, crl_digest)'''
					sql += ''' VALUES (%d, %d, %d, "%s")''' % (crl_uri_id, num_of_revoked, crl_size, base64.b64encode(crl_digest))
					try:
						cursor.execute(sql)
						crl_id = db.insert_id()
						db.commit()
					except MySQLdb.Error, e:
						db.rollback()
						print ("\tError7 %d: %s" % (e.args[0], e.args[1]))
						print ("\tError7 adding the CRL of [%s]" % x)
			except urllib2.URLError:
				#print ("\tError8 opening the CRL [%s] in [%s]" % (crl_uri, x))
				pass
			except:
				pass


		########################################################	
		##### Insert the certificate information to the DB #####
		
		serial_num = x509.get_serial_number()
		sig_alg = x509.get_signature_algorithm()
		#not_before = x509.get_notBefore()
		#not_after = x509.get_notAfter()
		key_length = x509.get_pubkey().bits()
		
		if crl_uri_id != -1 and auth_id != -1:
			sql = '''INSERT INTO certs(serial, alg, key_length, cert_pem, issuer_id, subject_id, crl_uri_id, auth_id)'''
			sql += ''' VALUES ("%s", "%s", %d, "%s", %d, %d, %d, %d);''' % (serial_num, sig_alg, key_length, cert, issuer_id, subject_id, crl_uri_id, auth_id)
		elif auth_id != -1:
			sql = '''INSERT INTO certs(serial, alg, key_length, cert_pem, issuer_id, subject_id, auth_id)'''
			sql += ''' VALUES ("%s", "%s", %d, "%s", %d, %d, %d);''' % (serial_num, sig_alg, key_length, cert, issuer_id, subject_id, auth_id)
		elif crl_uri_id != -1:
			sql = '''INSERT INTO certs(serial, alg, key_length, cert_pem, issuer_id, subject_id, crl_uri_id)'''
			sql += ''' VALUES ("%s", "%s", %d, "%s", %d, %d, %d);''' % (serial_num, sig_alg, key_length, cert, issuer_id, subject_id, crl_uri_id)
		else:
			sql = '''INSERT INTO certs(serial, alg, key_length, cert_pem, issuer_id, subject_id)'''
			sql += ''' VALUES ("%s", "%s", %d, "%s", %d, %d);''' % (serial_num, sig_alg, key_length, cert, issuer_id, subject_id)
		cert_id = -1
		try:
			cursor.execute(sql)
			cert_id = db.insert_id()
			db.commit()
		except MySQLdb.Error, e:
			if e.args[0] == 1062:
				#print ("\tThis certificate of [%s] is already in the DB" % subject.commonName)
				if index == 0:
					try:
						sql = '''SELECT cert_id FROM certs WHERE serial="%s" AND alg="%s" AND key_length=%d AND issuer_id=%d AND subject_id=%d''' % (serial_num, sig_alg, key_length, issuer_id, subject_id)
						cursor.execute(sql)
						cert_id = cursor.fetchone()[0]
					except MySQLdb.Error, e:
						print ("\tError9_2 %d: %s to connection [%s]" % (e.args[0], e.args[1], x))
					except Exception:
						print ("\tError9_3 in connecting to [%s]" % x)
			else:
				db.rollback()
				print ("\tError9 %d: %s" % (e.args[0], e.args[1]))
				print ("\tError9 saving the cert information in the DB in [%s]", x)
				

		##############################################################################
		##### Update the connection information to point to the leaf certificate #####

		if index == 0:
			sql = "UPDATE ssl_connec SET cert_id = %d WHERE conn_id = %d" % (cert_id, conn_id)
			try:
				cursor.execute(sql)
				conn_id = db.insert_id()
				db.commit()
			except MySQLdb.Error, e:
				db.rollback()
				print ("\tError10 %d: %s" % (e.args[0], e.args[1]))
				print ("\tError10 updating the connection information in the DB to point to the cert in [%s]", x)
	
	print ("Parsing [%s] is done" % x)
########################################################
# 	Clean up				       #		
########################################################
				
# disconnect from server
db.close()

'''
########################################################

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('63.245.217.20', 443))
sslSocket = socket.ssl(s)
#print repr(sslSocket.issuer())
s.close()
cert = ssl.get_server_certificate(('mozilla.com',443))
#print cert;
#crl = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_PEM, cert)
#crl = ssl.get_revoked(("mozilla.com",443))
#sslctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
#cert_chain = sslctx.load_cert_chain(cert)
#OpenSSL.crypto.load_crl(OpebSSL.crypto.FILETYPE_PEM, crl)
#print x509.get_subject().get_components()
#print X509Extension(crlDistributionPoints)

#urllib.request.urlopen('http://gtssl-crl.geotrust.com/crls/gtssl.crl')
response = urllib.urlopen('http://gtssl-crl.geotrust.com/crls/gtssl.crl')
crl = response.read()

#crl_x509 = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_DER,crl)
'''
