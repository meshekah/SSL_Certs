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
import threading
from Queue import Queue, Empty
import time
import thread
import multiprocessing
import os
import getopt
import psutil
import subprocess
import types
from pylab import *
import signal

#########################################################
#	The definition of thread to handle the		#
#	      for non-blocking reading from the PIPE    #
#########################################################
class reading_thread(threading.Thread):
	def __init__(self, out, queue):
		# Initialize the Threading
		threading.Thread.__init__(self)
		# a boolean which says this thread is allowed to live or not
		self.allowedToLive = True
		self.out = out
		self.queue = queue
		self.daemon = True
		# Start the timer and call self.nuke when it is reached
		self.t = threading.Timer(3,self.nuke)

	def run(self):
		self.t.start()
		if self.allowedToLive: 
			for line in iter(self.out.readline, b''):
				self.queue.put(line)
			self.out.close()
			pass
			self.allowedToLive = False
		# kill
		self.t.cancel()
		self.t = threading.Timer(1,self.nuke)
		self.t.start()

	def nuke(self):
		#if self.out.closed == False:
		#	self.out.close()
		sys.exit()


##############################################################################
#  This is just to spawn a thread for making the connection without blocking #
##############################################################################
class Open_uri(threading.Thread):
	def __init__(self, uri, res):
		# Initialize the Threading
		threading.Thread.__init__(self)
		# a boolean which says this thread is allowed to live or not
		self.allowedToLive = True
		self.res = res
		self.uri = uri
		self.daemon = True
		# Start the timer and call self.nuke when it is reached
		self.t = threading.Timer(3,self.nuke)

	def run(self):
		self.t.start()
		if self.allowedToLive:
			try:
				res = urllib2.urlopen(self.uri, None, 3.0)
				self.res.append(res)
				pass
				self.allowedToLive = False
			except Exception:
				res = list()
		# kill
		self.t.cancel()
		self.t = threading.Timer(1,self.nuke)
		self.t.start()

	def nuke(self):
		sys.exit()


#################################################################
#	Getting the connection blobs and saving them to a file 	#
# Assumes:						       	#
#	parse_certs_from_files() has been called before	       	#
#################################################################
def get_connecs(dir, L):	
	for index, x in enumerate(L):
		if (index % 100) == 0:
			print ("Process (%d) have processed %d URLs" % (os.getpid(), index))
		##### Make sure the connection valid with aggressive timeout #####
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
		s.settimeout(4);
		try:
			s.connect((x, 443));
		except socket.timeout:
			s.close()
			continue
		except Exception:
			continue
		s.close();
	
		###############################################################
		##### Running the openssl command to get the certificates #####
		pid = subprocess.Popen("echo GET | openssl s_client -connect %s:443 -showcerts" % x, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
		fin = pid.stdout
		qu = Queue()
		thr = reading_thread(fin, qu)
		thr.start()
		time.sleep(1)
		ssl_connec = ""
		while True:
			try:
				line = qu.get_nowait()
			except Empty:
				break
			else:
				ssl_connec += line
		f = open("%s/%s.txt" % (dir, x), "w")
		f.write(ssl_connec)
		f.close()
		del qu
		pid.kill()
	del L
	print ("Process (%d) is done" % os.getpid())


#################################################################
#	Getting the Certificates and saving them to a file 	#
# Assumes:						   	#
#	Nothing						   	#
#################################################################
def get_certs(dir, L):	
	for index, x in enumerate(L):
		if (index % 100) == 0:
			print ("Process (%d) have processed %d URLs" % (os.getpid(), index))
		##### Make sure the connection valid with aggressive timeout #####
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
		s.settimeout(4);
		try:
			s.connect((x, 443));
		except socket.timeout:
			s.close()
			continue
		except Exception:
			continue
		s.close();
	
		###############################################################
		##### Running the openssl command to get the certificates #####
		pid = subprocess.Popen("echo GET | openssl s_client -connect %s:443 -showcerts" % x, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
		fin = pid.stdout
		qu = Queue()
		thr = reading_thread(fin, qu)
		thr.start()
		time.sleep(1)
		i = 1
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
					f = open("%s/%s_%d.pem" % (dir, x, i), "wb")
					f.write(cert)
					f.close()
					i += 1
				##### End of Loop
		del qu
		del thr
		pid.terminate()
	del L
	print ("Process (%d) is done" % os.getpid())


#################################################################
#	Getting the Certificates and saving them to a file 	#
# Assumes:						   	#
#	Nothing.					   	#
#################################################################
def get_certs_connces(cert_dir, connec_dir, L):	
	for index, x in enumerate(L):
		if (index % 100) == 0:
			print ("Process (%d) have processed %d URLs" % (os.getpid(), index))
		##### Make sure the connection valid with aggressive timeout #####
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
		s.settimeout(4);
		try:
			s.connect((x, 443));
		except socket.timeout:
			s.close()
			continue
		except Exception:
			continue
		s.close();
		###############################################################
		##### Running the openssl command to get the certificates #####
		pid = subprocess.Popen("echo GET | openssl s_client -connect %s:443 -showcerts" % x, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
		fin = pid.stdout
		qu = Queue()
		thr = reading_thread(fin, qu)
		thr.start()
		time.sleep(1)
		i = 1
		certFound = 0
		ssl_connec = ""
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
					f = open("%s/%s_%d.pem" % (cert_dir, x,i), "wb")
					f.write(cert)
					f.close()
					i += 1
				ssl_connec += line
				##### End of Loop
		f = open("%s/%s.txt" % (connec_dir, x), "w")
		f.write(ssl_connec)
		f.close()
		del qu
		del thr
		pid.terminate()
	del L
	print ("Process (%d) is done" % os.getpid())


#########################################################################
# Reading the connections blob from a file, parsing it and saving the   #
#	information in the DB						#
# Assumes:								#
#	get_connecs() has been called before				#
#########################################################################
def parse_connecs(dir_path, L, top):
	########################################################
	# 	Prepare the DB connection		       #
	########################################################
	# Open database connection
	db = MySQLdb.connect("localhost","root","","CRL", charset='utf8' )
	# prepare a cursor object using cursor() method
	cursor = db.cursor()
	for index, file_name in enumerate(L):
		if file_name == ".DS_Store":
			continue
		if (index % 1000) == 0:
			print ("Process (%d) have processed (%d) connections" % (os.getpid(), index))
		cert_name = ""
		matchObj = re.search( r'^(.*).txt$', file_name, re.I|re.M)
		if matchObj:
			cert_name = matchObj.group(1)
		else:
			print ("Error - the certificate name cannot be pulled")
			sys.exit()
		# Get the certificate ID
		sql = '''SELECT cert_id FROM certs WHERE cert_name = "%s_1.pem" AND top = %d''' % (cert_name, top)
		cert_id = -1
		try:
			cursor.execute(sql)
			if cursor.rowcount == 0:
				pass
			else:
				cert_id = cursor.fetchone()[0]
		except Exception as ex:
			print ("Exception in fetching the cert_id - %s" % ex.args)
			sys.exit()
		file = open(os.path.join(dir_path,file_name), "r")
		ssl_session = 0
		protocol = ""
		cipher = ""
		for line in file.readlines():
			matchObj = re.search( r'^.*SSL-Session:.*$', line, re.I|re.M)
			if matchObj:
				ssl_session = 1
			matchObj = re.search( r'^.*[Pp]rotocol\s*:\s*(.*)$', line, re.I|re.M)
			if ssl_session == 1 and matchObj:
				protocol = matchObj.group(1)
			matchObj = re.search( r'^.*[Cc]ipher\s*:\s*(.*)$', line, re.I|re.M)
			if ssl_session == 1 and matchObj:
				cipher = matchObj.group(1)
		file.close()
		if cert_id == -1:
			sql = '''INSERT IGNORE INTO ssl_connecs(uri, top) VALUES ("%s", %d);''' % (cert_name, top)
		else:
			sql = '''INSERT INTO ssl_connecs(protocol, cipher, cert_id, uri, top) VALUES ("%s", "%s", %d, "%s", %d) ON DUPLICATE KEY UPDATE protocol="%s", cipher="%s";''' % (protocol, cipher, cert_id, cert_name, top, protocol, cipher)
		try:
			cursor.execute(sql)
		except Exception as ex:
			print ("Exception in inserting the connection information SQL [%s] - %s" % (sql,ex.args))
			sys.exit()
	##### Close the DB #####
	db.commit()
	db.close()


#########################################################################
# Reading the certificates from the file, parsing them and saving their #
#	information in the DB						#
# Assumes:								#
#	get_certs() has been called before.				#
#########################################################################
def parse_certs_from_files(dir_path, L, top):
	########################################################
	# 	Prepare the DB connection		       #
	########################################################
	# Open database connection
	db = MySQLdb.connect("localhost","root","","CRL", charset='utf8' )
	# prepare a cursor object using cursor() method
	cursor = db.cursor()
	for index, file_name in enumerate(L):
		if (index % 1000) == 0:
			print ("Process (%d) have processed (%d) certificates" % (os.getpid(), index))
		file = open(os.path.join(dir_path,file_name), "rb")
		cert = file.read()
		x509 = ""
		try:
			x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
		except:
			continue

	
		#########################################
		##### Insert the issuer information #####

		issuer = x509.get_issuer()
		if issuer.organizationName is not None:
			matchObj = re.search( r'^.*"(.*)".*$', issuer.organizationName, re.I|re.M)
			if matchObj:
				issuer.organizationName = matchObj.group(1)
		if issuer.organizationalUnitName is not None:
			matchObj = re.search( r'^.*"(.*)".*$', issuer.organizationalUnitName, re.I|re.M)
			if matchObj:
				issuer.organizationalUnitName = matchObj.group(1)
		if issuer.commonName is not None:
			matchObj = re.search( r'^.*"(.*)".*$', issuer.commonName, re.I|re.M)
			if matchObj:
				issuer.commonName = matchObj.group(1)
		if issuer.countryName is not None:
			matchObj = re.search( r'^.*"(.*)".*$', issuer.countryName, re.I|re.M)
			if matchObj:
				issuer.countryName = matchObj.group(1)
			else:
				matchObj  = re.search( r'^(.*)".*$', issuer.countryName, re.I|re.M)
				if matchObj:
					issuer.countryName = matchObj.group(1)
		sql = '''INSERT INTO names(country, org, org_unit, com_name, top) VALUES ("%s", "%s", "%s", "%s", %d) ON DUPLICATE KEY UPDATE name_id=LAST_INSERT_ID(name_id);''' % (issuer.countryName, issuer.organizationName, issuer.organizationalUnitName, issuer.commonName, top)
		Issuer_id = -1
		try:
			cursor.execute(sql)
			issuer_id = db.insert_id()
		except MySQLdb.Error, e:
			print ("\tError2 %d: %s SQL STMT [%s]" % (e.args[0], e.args[1], sql))
			print ("\tError2 saving the issuer information in the DB in [%s]" % file_name)
			sys.exit()


		##########################################	
		##### Insert the subject information #####

		subject = x509.get_subject()
		if subject.organizationName is not None:
			matchObj = re.search( r'^.*"(.*)".*$', subject.organizationName, re.I|re.M)
			if matchObj:
				subject.organizationName = matchObj.group(1)
		if subject.organizationalUnitName is not None:
			matchObj = re.search( r'^.*"(.*)".*$', subject.organizationalUnitName, re.I|re.M)
			if matchObj:
				subject.organizationalUnitName = matchObj.group(1)
		if subject.commonName is not None:
			matchObj = re.search( r'^.*"(.*)".*$', subject.commonName, re.I|re.M)
			if matchObj:
				subject.commonName = matchObj.group(1)
		if subject.countryName is not None:
			matchObj = re.search( r'^.*"(.*)".*$', subject.countryName, re.I|re.M)
			if matchObj:
				subject.countryName = matchObj.group(1)
			else:
				matchObj  = re.search( r'^(.*)".*$', subject.countryName, re.I|re.M)
				if matchObj:
					subject.countryName = matchObj.group(1)
		sql = '''INSERT INTO names(country, org, org_unit, com_name, top) VALUES ("%s", "%s", "%s", "%s", %d) ON DUPLICATE KEY UPDATE name_id=LAST_INSERT_ID(name_id);''' % (subject.countryName, subject.organizationName, subject.organizationalUnitName, subject.commonName, top)
		subject_id = -1
		try:
			cursor.execute(sql)
			subject_id = db.insert_id()
		except MySQLdb.Error, e:
			print ("\tError3 %d: %s" % (e.args[0], e.args[1]))
			print ("\tError3 saving the subject information in the DB in [%s] with SQL [%s]" % (file_name, sql))
			sys.exit()

		#################################
		##### Check if self  signed #####
		is_self_signed = 0
		if (subject.get_components()) == (issuer.get_components()):
			is_self_signed = 1


		##############################
		##### Get the Extensions #####
		
		crl_points = list()
		auth_points = list()
		ext_count = x509.get_extension_count()
		for i in range (0, ext_count):
			x509_ext = x509.get_extension(i)
			ext_name = x509_ext.get_short_name()
			matchObj = re.search( r'^.*crlDistributionPoints.*$', ext_name, re.I|re.M)
			if matchObj:
				ext_data_der = x509_ext.get_data()
				der_seq = asn1.DerSequence()
				der_seq.decode(ext_data_der)
				for u in range(len(der_seq)):
					der_obj = asn1.DerObject()
					der_obj.decode(der_seq[u])
					matchObj = re.search( r'^.*(http[s]?:[\w\d=/\.%-_!]+).*$', der_obj.payload, re.I|re.M)
					if matchObj:
						try:
							crl_uri = matchObj.group(1)
							crl_points.append(crl_uri)
						except:
							print ("\tError3_1 error getting the CRL URI [%s] when connecting to [%s]" % (ext_data, file_name))
							sys.exit()
					else:
						if (re.search( r'^.*(http.*).*$', der_obj.payload, re.I|re.M)):
							print ("\tError3_3 extracting the URI from [%s]" % der_obj.payload)
						else:
							pass
			matchObj = re.search( r'^.*authorityInfoAccess.*$', ext_name, re.I|re.M)
			if matchObj:
				ext_data_der = x509_ext.get_data()
				der_seq = asn1.DerSequence()
				der_seq.decode(ext_data_der)
				for u in range(len(der_seq)):
					der_obj = asn1.DerObject()
					der_obj.decode(der_seq[u])
					matchObj = re.search( r'^.*(http:.*)$', der_obj.payload, re.I|re.M)
					if matchObj:
						try:
							auth_uri = matchObj.group(1)
							auth_points.append(auth_uri)
						except:
							print ("\tError3_2 error getting the Auth URI [%s] when connecting to [%s]" % (ext_data, file_name))
							sys.exit()
				
		
		##############################################
		##### Insert the Authority URI in the DB #####
		
		auth_ids = list()
		if len(auth_points) > 0:
			for auth_uri in auth_points:
				sql = '''INSERT INTO authority(auth_uri, top) VALUES ("%s", %d) ON DUPLICATE KEY UPDATE auth_id=LAST_INSERT_ID(auth_id);''' % (auth_uri, top)
				try:
					cursor.execute(sql)
					auth_id = db.insert_id()
					auth_ids.append(auth_id)
				except MySQLdb.Error, e:
					print ("\tError4 %d: %s" % (e.args[0], e.args[1]))
					print ("\tError4 saving the Authority information in the DB in [%s]", file_name)
					sys.exit()	


		########################################
		##### Insert the CRL URI in the DB #####
		
		crl_uri_ids = list()
		if len(crl_points) > 0:
			for crl_uri in crl_points:
				sql = '''INSERT INTO crls_uri(crl_uri, top) VALUES ("%s", %d) ON DUPLICATE KEY UPDATE crl_uri_id=LAST_INSERT_ID(crl_uri_id);''' % (crl_uri, top)
				try:
					cursor.execute(sql)
					crl_uri_id = db.insert_id()
					crl_uri_ids.append(crl_uri_id)
				except MySQLdb.Error, e:
					print ("\tError5 %d: %s SQL STMT [%s]" % (e.args[0], e.args[1], sql))
					print ("\tError5 saving the CRL URI [%s] in the DB in [%s]" % (crl_uri, file_name))
	

		########################################################	
		##### Insert the certificate information to the DB #####
	

		cert_id = -1
		try:
			serial_num = x509.get_serial_number()
			sig_alg = x509.get_signature_algorithm()
			version = x509.get_version()
			key_length = x509.get_pubkey().bits()
			digest = hashlib.sha224()
			digest.update(cert)
			cert_digest = digest.digest()
			cert_digest = base64.b64encode(cert_digest)
			sql = '''INSERT INTO certs(serial, alg, key_length, cert_digest, issuer_id, subject_id, top, cert_name, is_self_signed, version)'''
			sql += ''' VALUES ("%s", "%s", %d, "%s", %d, %d, %d, "%s", %d, "%s") ON DUPLICATE KEY UPDATE cert_id=LAST_INSERT_ID(cert_id), cert_name = "%s";''' % (serial_num, sig_alg, key_length, cert_digest, issuer_id, subject_id, top, file_name, is_self_signed, file_name, version)
			cursor.execute(sql)
			cert_id = db.insert_id()
		except MySQLdb.Error, e:
			print ("\tError9 %d: %s SQL STMT [%s]" % (e.args[0], e.args[1], sql))
			print ("\tError9 saving the cert information in the DB in [%s]", file_name)
			sys.exit()
		except Exception as ex:
			if type(ex) is OpenSSL.crypto.Error:
				print ("Error9_1 - Error in the crypto library")
				print (ex.args)
				continue
		if len(crl_uri_ids) > 0:
			for crl_uri_id in crl_uri_ids:
				sql = '''INSERT IGNORE INTO certs_crls(crl_uri_id, cert_id) VALUES (%d, %d)''' % (crl_uri_id, cert_id)
				try:
					cursor.execute(sql)
				except MySQLdb.Error, e:
					print ("\tError10 %d: %s SQL STMT [%s]" % (e.args[0], e.args[1], sql))
					print ("\tError10 saving the CERT_CRL information in the DB in [%s]" % file_name)
					sys.exit()
		if len(auth_ids) > 0:
			for auth_id in auth_ids:
				sql = '''INSERT IGNORE INTO certs_auths(auth_id, cert_id) VALUES (%d, %d)''' % (auth_id, cert_id)
				try:
					cursor.execute(sql)
				except MySQLdb.Error, e:
					print ("\tError11 %d: %s SQL STMT [%s]" % (e.args[0], e.args[1], sql))
					print ("\tError11 saving the AUTH_CRL information in the DB in [%s]" %	 file_name)
					sys.exit()
	
	##### Close the DB #####
	db.commit()
	db.close()


#########################################################################
# Reading the certificates from the connection blob file, parsing them	#
#	and saving their information in the DB				#
# Assumes:								#
#	get_connecs() has been called before				#
#########################################################################
def parse_certs_from_connecs(dir_path, L, top):
	# Open database connection
	db = MySQLdb.connect("localhost","root","","CRL", charset='utf8' )
	# prepare a cursor object using cursor() method
	cursor = db.cursor()
	for index, file_name in enumerate(L):
		if (index % 1000) == 0:
			print ("(%d) connection blobs have been processed" % (index))
		matchObj = re.search( r'^(.*).txt$', file_name, re.I|re.M)
		if matchObj:
			uri = matchObj.group(1)
		file = open(os.path.join(dir_path,file_name), "r")
		ssl_session = 0
		protocol = ""
		cipher = ""
		certFound = 0
		certs = list()
		for line in file.readlines():
			if (certFound == 1):
					cert += line
			matchObj = re.search( r'BEGIN CERTIFICATE', line, re.I|re.M)
			if matchObj:
				certFound = 1
				cert = line;
			matchObj = re.search( r'END CERTIFICATE', line, re.I|re.M)
			if matchObj:
				certFound = 0;
				certs.append(cert)
			matchObj = re.search( r'^.*SSL-Session:.*$', line, re.I|re.M)
			if matchObj:
				ssl_session = 1
			matchObj = re.search( r'^.*[Pp]rotocol\s*:\s*(.*)$', line, re.I|re.M)
			if ssl_session == 1 and matchObj:
				protocol = matchObj.group(1)
			matchObj = re.search( r'^.*[Cc]ipher\s*:\s*(.*)$', line, re.I|re.M)
			if ssl_session == 1 and matchObj:
				cipher = matchObj.group(1)
		file.close()
		certs.reverse()
		num_of_certs = len(certs)
		prev_cert_id = -1
		iden_cert_id = -1
		for j, cert in enumerate(certs):
			cert_name = "%s_%d.pem" % (uri, (num_of_certs - j))
			x509 = ""
			try:
				x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
			except:
				continue
			
			#########################################
			##### Insert the issuer information #####
			issuer = x509.get_issuer()
			if issuer.organizationName is not None:
				matchObj = re.search( r'^.*"(.*)".*$', issuer.organizationName, re.I|re.M)
				if matchObj:
					issuer.organizationName = matchObj.group(1)
			if issuer.organizationalUnitName is not None:
				matchObj = re.search( r'^.*"(.*)".*$', issuer.organizationalUnitName, re.I|re.M)
				if matchObj:
					issuer.organizationalUnitName = matchObj.group(1)
			if issuer.commonName is not None:
				matchObj = re.search( r'^.*"(.*)".*$', issuer.commonName, re.I|re.M)
				if matchObj:
					issuer.commonName = matchObj.group(1)
			if issuer.countryName is not None:
				matchObj = re.search( r'^.*"(.*)".*$', issuer.countryName, re.I|re.M)
				if matchObj:
					issuer.countryName = matchObj.group(1)
				else:
					matchObj  = re.search( r'^(.*)".*$', issuer.countryName, re.I|re.M)
					if matchObj:
						issuer.countryName = matchObj.group(1)
			sql = '''INSERT INTO names(country, org, org_unit, com_name, top) VALUES ("%s", "%s", "%s", "%s", %d) ON DUPLICATE KEY UPDATE name_id=LAST_INSERT_ID(name_id);''' % (issuer.countryName, issuer.organizationName, issuer.organizationalUnitName, issuer.commonName, top)
			Issuer_id = -1
			try:
				cursor.execute(sql)
				issuer_id = db.insert_id()
			except MySQLdb.Error, e:
				print ("\tError2 %d: %s SQL STMT [%s]" % (e.args[0], e.args[1], sql))
				print ("\tError2 saving the issuer information in the DB in [%s]" % file_name)
				sys.exit()
	
	
			##########################################	
			##### Insert the subject information #####
			subject = x509.get_subject()
			if subject.organizationName is not None:
				matchObj = re.search( r'^.*"(.*)".*$', subject.organizationName, re.I|re.M)
				if matchObj:
					subject.organizationName = matchObj.group(1)
			if subject.organizationalUnitName is not None:
				matchObj = re.search( r'^.*"(.*)".*$', subject.organizationalUnitName, re.I|re.M)
				if matchObj:
					subject.organizationalUnitName = matchObj.group(1)
			if subject.commonName is not None:
				matchObj = re.search( r'^.*"(.*)".*$', subject.commonName, re.I|re.M)
				if matchObj:
					subject.commonName = matchObj.group(1)
			if subject.countryName is not None:
				matchObj = re.search( r'^.*"(.*)".*$', subject.countryName, re.I|re.M)
				if matchObj:
					subject.countryName = matchObj.group(1)
				else:
					matchObj  = re.search( r'^(.*)".*$', subject.countryName, re.I|re.M)
					if matchObj:
						subject.countryName = matchObj.group(1)
			sql = '''INSERT INTO names(country, org, org_unit, com_name, top) VALUES ("%s", "%s", "%s", "%s", %d) ON DUPLICATE KEY UPDATE name_id=LAST_INSERT_ID(name_id);''' % (subject.countryName, subject.organizationName, subject.organizationalUnitName, subject.commonName, top)
			subject_id = -1
			try:
				cursor.execute(sql)
				subject_id = db.insert_id()
			except MySQLdb.Error, e:
				print ("\tError3 %d: %s" % (e.args[0], e.args[1]))
				print ("\tError3 saving the subject information in the DB in [%s] with SQL [%s]" % (file_name, sql))
				sys.exit()
	
			################################
			##### Check if self signed #####
			is_self_signed = 0
			if (subject.get_components()) == (issuer.get_components()):
				is_self_signed = 1
	
			##############################
			##### Get the Extensions #####
			crl_points = list()
			auth_points = list()
			ext_count = x509.get_extension_count()
			for i in range (0, ext_count):
				x509_ext = x509.get_extension(i)
				ext_name = x509_ext.get_short_name()
				matchObj = re.search( r'^.*crlDistributionPoints.*$', ext_name, re.I|re.M)
				if matchObj:
					ext_data_der = x509_ext.get_data()
					der_seq = asn1.DerSequence()
					der_seq.decode(ext_data_der)
					for u in range(len(der_seq)):
						der_obj = asn1.DerObject()
						der_obj.decode(der_seq[u])
						matchObj = re.search( r'^.*(http[s]?:[\w\d=/\.%-_!]+).*$', der_obj.payload, re.I|re.M)
						if matchObj:
							try:
								crl_uri = matchObj.group(1)
								crl_points.append(crl_uri)
							except:
								print ("\tError3_1 error getting the CRL URI [%s] when connecting to [%s]" % (ext_data, file_name))
								sys.exit()
						else:
							if (re.search( r'^.*(http.*).*$', der_obj.payload, re.I|re.M)):
								print ("\tError3_3 extracting the URI from [%s]" % der_obj.payload)
							else:
								pass
				matchObj = re.search( r'^.*authorityInfoAccess.*$', ext_name, re.I|re.M)
				if matchObj:
					ext_data_der = x509_ext.get_data()
					der_seq = asn1.DerSequence()
					der_seq.decode(ext_data_der)
					for u in range(len(der_seq)):
						der_obj = asn1.DerObject()
						der_obj.decode(der_seq[u])
						matchObj = re.search( r'^.*(http:.*)$', der_obj.payload, re.I|re.M)
						if matchObj:
							try:
								auth_uri = matchObj.group(1)
								auth_points.append(auth_uri)
							except:
								print ("\tError3_2 error getting the Auth URI [%s] when connecting to [%s]" % (ext_data, file_name))
								sys.exit()
					
			
			##############################################
			##### Insert the Authority URI in the DB #####
			
			auth_ids = list()
			if len(auth_points) > 0:
				for auth_uri in auth_points:
					sql = '''INSERT INTO authority(auth_uri, top) VALUES ("%s", %d) ON DUPLICATE KEY UPDATE auth_id=LAST_INSERT_ID(auth_id);''' % (auth_uri, top)
					try:
						cursor.execute(sql)
						auth_id = db.insert_id()
						auth_ids.append(auth_id)
					except MySQLdb.Error, e:
						print ("\tError4 %d: %s" % (e.args[0], e.args[1]))
						print ("\tError4 saving the Authority information in the DB in [%s]", file_name)
						sys.exit()	
	
			########################################
			##### Insert the CRL URI in the DB #####
			crl_uri_ids = list()
			if len(crl_points) > 0:
				for crl_uri in crl_points:
					sql = '''INSERT INTO crls_uri(crl_uri, top) VALUES ("%s", %d) ON DUPLICATE KEY UPDATE crl_uri_id=LAST_INSERT_ID(crl_uri_id);''' % (crl_uri, top)
					try:
						cursor.execute(sql)
						crl_uri_id = db.insert_id()
						crl_uri_ids.append(crl_uri_id)
					except MySQLdb.Error, e:
						print ("\tError5 %d: %s SQL STMT [%s]" % (e.args[0], e.args[1], sql))
						print ("\tError5 saving the CRL URI [%s] in the DB in [%s]" % (crl_uri, file_name))
	
			########################################################	
			##### Insert the certificate information to the DB #####
			cert_id = -1
			try:
				serial_num = x509.get_serial_number()
				sig_alg = x509.get_signature_algorithm()
				version = x509.get_version()
				version += 1
				try:
					key_length = x509.get_pubkey().bits()
				except Exception:
					key_length = -1
				digest = hashlib.sha224()
				digest.update(cert)
				cert_digest = digest.digest()
				cert_digest = base64.b64encode(cert_digest)
				if j == 0:
					sql = '''INSERT INTO certs(serial, alg, key_length, cert_digest, issuer_id, subject_id, top, cert_name, is_self_signed, version)'''
					sql += ''' VALUES ("%s", "%s", %d, "%s", %d, %d, %d, "%s", %d, "%s") ON DUPLICATE KEY UPDATE cert_id=LAST_INSERT_ID(cert_id), cert_name = "%s";''' % (serial_num, sig_alg, key_length, cert_digest, issuer_id, subject_id, top, cert_name, is_self_signed, version, cert_name)
				else:					
					sql = '''INSERT INTO certs(serial, alg, key_length, cert_digest, issuer_id, subject_id, top, cert_name, is_self_signed, version, parent_cert_id)'''
					sql += ''' VALUES ("%s", "%s", %d, "%s", %d, %d, %d, "%s", %d, "%s", %d) ON DUPLICATE KEY UPDATE cert_id=LAST_INSERT_ID(cert_id), cert_name = "%s";''' % (serial_num, sig_alg, key_length, cert_digest, issuer_id, subject_id, top, cert_name, is_self_signed, version, prev_cert_id, cert_name)
				cursor.execute(sql)
				cert_id = db.insert_id()
				prev_cert_id = cert_id
				if j == (num_of_certs - 1):
					iden_cert_id = cert_id
			except MySQLdb.Error, e:
				print ("\tError9 %d: %s SQL STMT [%s]" % (e.args[0], e.args[1], sql))
				print ("\tError9 saving the cert information in the DB in [%s]", file_name)
				sys.exit()
			except Exception as ex:
				if type(ex) is OpenSSL.crypto.Error:
					print ("Error9_1 - Error in the crypto library")
					print (ex.args)
					sys.exit()
			if len(crl_uri_ids) > 0:
				for crl_uri_id in crl_uri_ids:
					sql = '''INSERT IGNORE INTO certs_crls(crl_uri_id, cert_id) VALUES (%d, %d)''' % (crl_uri_id, cert_id)
					try:
						cursor.execute(sql)
					except MySQLdb.Error, e:
						print ("\tError10 %d: %s SQL STMT [%s]" % (e.args[0], e.args[1], sql))
						print ("\tError10 saving the CERT_CRL information in the DB in [%s]" % file_name)
						sys.exit()
			if len(auth_ids) > 0:
				for auth_id in auth_ids:
					sql = '''INSERT IGNORE INTO certs_auths(auth_id, cert_id) VALUES (%d, %d)''' % (auth_id, cert_id)
					try:
						cursor.execute(sql)
					except MySQLdb.Error, e:
						print ("\tError11 %d: %s SQL STMT [%s]" % (e.args[0], e.args[1], sql))
						print ("\tError11 saving the AUTH_CRL information in the DB in [%s]" %	 file_name)
						sys.exit()
		if len(certs) == 0:
			sql = '''INSERT IGNORE INTO ssl_connecs(uri, top) VALUES ("%s", %d);''' % (uri, top)
		else:
			sql = '''INSERT INTO ssl_connecs(protocol, cipher, cert_id, uri, top) VALUES ("%s", "%s", %d, "%s", %d) ON DUPLICATE KEY UPDATE protocol="%s", cipher="%s";''' % (protocol, cipher, cert_id, uri, top, protocol, cipher)
		try:
			cursor.execute(sql)
		except Exception as ex:
			print ("Exception in inserting the connection information SQL [%s] - %s" % (sql,ex.args))
			sys.exit()
	##### Close the DB #####
	db.commit()
	db.close()


#########################################################################
# Reading the CRL URIs, opening them, saving their information in the  	#
#	DB and then saving them in a file. 				#
# Assumes:								#
#	parse_certs_from_files() has been called before OR		#
#	parse_certs_from_connecs() has been called before		#
#########################################################################
def get_CRLs(dir_path, L, top):
	########################################################
	# 	Prepare the DB connection		       #
	########################################################
	
	# Open database connection
	db = MySQLdb.connect("localhost","root","","CRL", charset='utf8' )	
	# prepare a cursor object using cursor() method
	cursor = db.cursor()
	# Number of bad URIs
	num_bad_uri = 0
	# Number of timed-out URI
	num_time_out = 0
	# Number of bad CRLs
	num_bad_crls = 0
	for index, crl_row in enumerate(L):
		if (index % 50) == 0:
			print ("(%d) CRLs have been fetched" % index)
		print (str(index + 1) + " - " + str(crl_row[0]) + " - " + str(crl_row[1]))

		#################################################
		##### Getting the CRL Object and parsing it #####
		crl_uri_id = crl_row[0]
		crl_id = -1
		try:
			##### Reasons for revoking #####
			rNone = 0
			unspecified = 0
			keyCompromise = 0
			cACompromise = 0
			affiliationChanged = 0
			superseded = 0
			cessationOfOperation = 0
			certificateHold = 0
			removeFromCRL = 0
			privilegeWithdrawn = 0
			aACompromise = 0
			socket.setdefaulttimeout(2)
			myL = list()
			thr = Open_uri(crl_row[1], myL)
			thr.start()
			k = 0
			while True:
				if len(myL) > 0:
					break
				elif k > 4:
					raise socket.timeout
				else:
					time.sleep(1)
					k += 1
			res = myL[0]
			crl_der = res.read()
			digest = hashlib.sha224()
			digest.update(crl_der)
			crl_digest = digest.digest()
			crl_digest = base64.b64encode(crl_digest)
			crl_size = len(crl_der)
			crl = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, crl_der)
			revoked = crl.get_revoked()
			num_of_revoked = -1
			if revoked is not None or len(revoked) == 0:
				num_of_revoked = len(revoked)
				for rev in revoked:
					reason = rev.get_reason()
					reason = str(reason)
					if reason == "None":
						rNone += 1
					elif reason == "unspecified" or reason == "Unspecified" or reason == "0":
						unspecified += 1
					elif reason == "keyCompromise" or reason == "Key Compromise" or reason == "1":
						keyCompromise += 1
					elif reason == "cACompromise" or reason == "CA Compromise" or reason == "2":
						cACompromise += 1
					elif reason == "affiliationChanged" or reason == "Affiliation Changed" or reason == "3":
						affiliationChanged += 1
					elif reason == "superseded" or reason == "Superseded" or reason == "4":
						superseded += 1
					elif reason == "cessationOfOperation" or reason == "Cessation Of Operation" or reason == "5":
						cessationOfOperation += 1
					elif reason == "certificateHold" or reason == "Certificate Hold" or reason == "6":
						certificateHold += 1
					elif reason == "removeFromCRL" or reason == "Remove From CRL" or reason == "8":
						removeFromCRL += 1
					elif reason == "privilegeWithdrawn" or reason == "Privilege Withdrawn" or reason == "9":
						privilegeWithdrawn += 1
					elif reason == "aACompromise" or reason == "AA Compromise" or reason == "10":
						aACompromise += 1
					else:
						print ("Unrecognized revocation reason [%s]" % reason)
			sql = '''INSERT IGNORE INTO crls(crl_uri_id, num_of_revoked, crl_size, crl_digest, rNone, unspecified, keyCompromise, cACompromise, affiliationChanged, superseded, cessationOfOperation, certificateHold, removeFromCRL, privilegeWithdrawn, aACompromise) '''
			sql += '''VALUES (%d, %d, %d, "%s", %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d)''' % (crl_uri_id, num_of_revoked, crl_size, crl_digest, rNone, unspecified, keyCompromise, cACompromise, affiliationChanged, superseded, cessationOfOperation, certificateHold, removeFromCRL, privilegeWithdrawn, aACompromise)
			try:
				cursor.execute(sql)
				crl_id = db.insert_id()
			except MySQLdb.Error, e:
				print ("\tError7 %d: %s SQL STMT [%s]" % (e.args[0], e.args[1], sql))
				print ("\tError7 adding the CRL of [%s]" % crl_row[1])
				sys.exit()
			
			##### Clean Up
			thr.join()
			del thr
			del myL
			
			################################################
			##### Saving the CRL information in a file #####
			f = open("%s/%d.crl" % (dir_path, crl_id), "wb")
			f.write(crl_der)
			f.close()
		except urllib2.URLError as ex:
			if type(ex) is urllib2.HTTPError:
				num_bad_uri += 1
			else:
				reason = ex.args[0]
				if reason == "no host given":
					num_bad_uri += 1
				elif str(reason) == "[Errno 8] nodename nor servname provided, or not known":
					num_bad_uri += 1
				elif str(reason) == "[Errno 61] Connection refused":
					num_bad_uri += 1
				elif str(reason) == "[Errno 8] _ssl.c:503: EOF occurred in violation of protocol":
					num_bad_uri += 1
				elif str(reason) == "[Errno 54] Connection reset by peer":
					num_bad_uri += 1
				elif str(reason) == "timed out":
					num_time_out += 1
				else:
					print ("\tError7_1 in the URI of CRL [%s]" % crl_row[1])
					print ("\t" + str(reason))
		except Exception as ex:
			if type(ex) is OpenSSL.crypto.Error:
				num_bad_crls += 1
			elif type(ex) is socket.timeout:
				#print ("\tSocket timed out connection to [%s]" % crl_row[1])
				num_time_out += 1
			else:
				print ("\tError8 with CRL of [%s]" % crl_row[1])
				print (ex.args)
				print (type(ex))
				continue
	print ("We Had (%d) bad URIs, (%d) URIs that timed out and (%d) bad CRL objects" % (num_bad_uri, num_time_out, num_bad_crls))
	
	##### Close the DB #####
	db.commit()
	db.close()


#########################################################################
# Parse the CRL objects, and save their information in the DB		#
# Assumes:								#
#	get_CRLs() has been executed					#
#########################################################################
def parse_CRLs(L):
	# Open database connection
	db = MySQLdb.connect("localhost","root","","CRL", charset='utf8' )	
	# prepare a cursor object using cursor() method
	cursor = db.cursor()
	# Number of bad CRLs
	num_bad_crls = 0
	for index, crl_obj in enumerate(L):
		if (index % 50) == 0:
			print ("(%d) CRLs have been parsed" % index)
		##################################
		##### Parsing the CRL Object #####
#		crl_uri_id = crl_row[0]
		crl_id = -1
		try:
			##### Reasons for revoking #####
			rNone = 0
			unspecified = 0
			keyCompromise = 0
			cACompromise = 0
			affiliationChanged = 0
			superseded = 0
			cessationOfOperation = 0
			certificateHold = 0
			removeFromCRL = 0
			privilegeWithdrawn = 0
			aACompromise = 0
			digest = hashlib.sha224()
			digest.update(crl_obj)
			crl_digest = digest.digest()
			crl_digest = base64.b64encode(crl_digest)
			crl_size = len(crl_obj)
			crl = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, crl_obj)
			revoked = crl.get_revoked()
			num_of_revoked = -1
			if revoked is not None:
				num_of_revoked = len(revoked)
				for rev in revoked:
					reason = rev.get_reason()
					reason = str(reason)
					if reason == "None":
						rNone += 1
					elif reason == "unspecified" or reason == "Unspecified" or reason == "0":
						unspecified += 1
					elif reason == "keyCompromise" or reason == "Key Compromise" or reason == "1":
						keyCompromise += 1
					elif reason == "cACompromise" or reason == "CA Compromise" or reason == "2":
						cACompromise += 1
					elif reason == "affiliationChanged" or reason == "Affiliation Changed" or reason == "3":
						affiliationChanged += 1
					elif reason == "superseded" or reason == "Superseded" or reason == "4":
						superseded += 1
					elif reason == "cessationOfOperation" or reason == "Cessation Of Operation" or reason == "5":
						cessationOfOperation += 1
					elif reason == "certificateHold" or reason == "Certificate Hold" or reason == "6":
						certificateHold += 1
					elif reason == "removeFromCRL" or reason == "Remove From CRL" or reason == "8":
						removeFromCRL += 1
					elif reason == "privilegeWithdrawn" or reason == "Privilege Withdrawn" or reason == "9":
						privilegeWithdrawn += 1
					elif reason == "aACompromise" or reason == "AA Compromise" or reason == "10":
						aACompromise += 1
					else:
						print ("Unrecognized revocation reason [%s]" % reason)
			##############################
			##### Get the CRL URI ID #####
			
			sql = '''INSERT IGNORE INTO crls(crl_uri_id, num_of_revoked, crl_size, crl_digest, rNone, unspecified, keyCompromise, cACompromise, affiliationChanged, superseded, cessationOfOperation, certificateHold, removeFromCRL, privilegeWithdrawn, aACompromise) '''
			sql += '''VALUES (%d, %d, %d, "%s", %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d)''' % (crl_uri_id, num_of_revoked, crl_size, crl_digest, rNone, unspecified, keyCompromise, cACompromise, affiliationChanged, superseded, cessationOfOperation, certificateHold, removeFromCRL, privilegeWithdrawn, aACompromise)
			try:
				cursor.execute(sql)
				crl_id = db.insert_id()
			except MySQLdb.Error, e:
				print ("\tError7 %d: %s SQL STMT [%s]" % (e.args[0], e.args[1], sql))
				print ("\tError7 adding the CRL of [%s]" % crl_row[1])
				sys.exit()
			
			##### Clean Up
			thr.join()
			del thr
			del myL
			
			################################################
			##### Saving the CRL information in a file #####
			f = open("../CRLs_100k_%d/%d.crl" % (top, crl_id), "wb")
			f.write(crl_der)
			f.close()
		except urllib2.URLError as ex:
			if type(ex) is urllib2.HTTPError:
				num_bad_uri += 1
			else:
				reason = ex.args[0]
				if reason == "no host given":
					num_bad_uri += 1
				elif str(reason) == "[Errno 8] nodename nor servname provided, or not known":
					num_bad_uri += 1
				elif str(reason) == "[Errno 61] Connection refused":
					num_bad_uri += 1
				elif str(reason) == "[Errno 8] _ssl.c:503: EOF occurred in violation of protocol":
					num_bad_uri += 1
				elif str(reason) == "[Errno 54] Connection reset by peer":
					num_bad_uri += 1
				elif str(reason) == "timed out":
					num_time_out += 1
				else:
					print ("\tError7_1 in the URI of CRL [%s]" % crl_row[1])
					print ("\t" + str(reason))
		except Exception as ex:
			if type(ex) is OpenSSL.crypto.Error:
				num_bad_crls += 1
			elif type(ex) is socket.timeout:
				#print ("\tSocket timed out connection to [%s]" % crl_row[1])
				num_time_out += 1
			else:
				print ("\tError8 with CRL of [%s]" % crl_row[1])
				print (ex.args)
				print (type(ex))
				continue
	print ("We Had (%d) bad URIs, (%d) URIs that timed out and (%d) bad CRL objects" % (num_bad_uri, num_time_out, num_bad_crls))
	
	##### Close the DB #####
	db.commit()
	db.close()

#########################################################
# 		Main program				#
#########################################################
def main(argv):
	if len(argv) == 0:
		print ("usage: wrong argument")
		sys.exit(2)
	module = ""
	top = -1
	try:
		opts, args = getopt.getopt(argv,"hm:a:",["mod=","arg="])
	except getopt.GetoptError:
		print ('usage: crl_crawling.py -m <module> -a <argument>')
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print ('usage: crl_crawling.py -m <module> -a <argument>')
			sys.exit()
		elif opt in ("-m", "--module"):
			module = arg
		elif opt in ("-a", "--argument"):
			top = arg
	print ('Module is [%s]' % module, end=' ')
	print ('for the top (%s)' % top)
	top = int(top)
	if module == "":
		print ('usage: crl_crawling.py -m <module> -a <argument>')
		sys.exit()
	
	##### Getting the Connections #####
	####################################
	if module == "get_connecs":
		if top < 1 or top > 10:
			print ('usage: crl_crawling.py -m <module> -a <argument>')
			sys.exit()
		L = list()
		with open('/Users/malmeshekah/Documents/SSL_Certs/data/top-100k_%d.csv' % top, 'rb') as csvf:
			csvreader = csv.reader(csvf)
			for csvrow in csvreader:
				L.append(csvrow[1])
			csvf.close()
		print ("Global List size %d" % len(L))
		jobs = []
		dir = "/Users/malmeshekah/Documents/obser/CONNECs_100k_%d" % top
		for i in range(100):
			x = i * 1000
			y = (i+1) * 1000
			L2 = L[x:y]
			p = multiprocessing.Process(target=get_connecs, args=(dir, L2,))
			jobs.append(p)
			p.start()
			del L2
		del L
		
	##### Parsing the Connections #####
	####################################
	elif module == "parse_connecs":
		if top < 1 or top > 10:
			print ('usage: crl_crawling.py -m <module> -a <argument>')
			sys.exit()
		L = list()
		jobs = []
		dir_path = "/Users/malmeshekah/Documents/obser/CONNECs_100k_%d" % top
		files = os.listdir(dir_path)
		for file_name in (files):
			L.append(file_name)
		print ("We have to parse %d connections" % len(L))
		parse_connecs(dir_path, L, top)
		del L
	
	##### Getting the Certificates #####
	####################################
	elif module == "get_certs":
		if top < 1 or top > 10:
			print ('usage: crl_crawling.py -m <module> -a <argument>')
			sys.exit()
		L = list()
		with open('/Users/malmeshekah/Documents/SSL_Certs/data/top-100k_%d.csv' % top, 'rb') as csvf:
			csvreader = csv.reader(csvf)
			for csvrow in csvreader:
				L.append(csvrow[1])
			csvf.close()
		print ("Global List size %d" % len(L))
		jobs = []
		for i in range(100):
			x = i * 1000
			y = (i+1) * 1000
			L2 = L[x:y]
			dir = "/Users/malmeshekah/Documents/obser/CERTs_100k_%d" % top
			p = multiprocessing.Process(target=get_certs, args=(dir, L2,))
			jobs.append(p)
			p.start()
			del L2
		del L
		
	##### Parsing the Certificates #####
	####################################
	elif module == "parse_certs_from_files":
		if top < 1 or top > 10:
			print ('usage: crl_crawling.py -m <module> -a <argument>')
			sys.exit()
		L = list()
		jobs = []
		dir_path = "/Users/malmeshekah/Documents/obser/CERTs_100k_%d" % top
		files = os.listdir(dir_path)
		for file_name in (files):
			L.append(file_name)
		print ("We have to parse %d certificates" % len(L))
		parse_certs_from_files(dir_path, L, top)
		del L
	
		##### Parsing the Certificates #####
	####################################
	elif module == "parse_certs_from_connecs":
		if top < 1 or top > 10:
			print ('usage: crl_crawling.py -m <module> -a <argument>')
			sys.exit()
		L = list()
		jobs = []
		dir_path = "/Users/malmeshekah/Documents/obser/CONNECs_100k_%d" % top
		files = os.listdir(dir_path)
		for file_name in (files):
			L.append(file_name)
		print ("We have to parse %d connections blobs" % len(L))
		parse_certs_from_connecs(dir_path, L, top)
		del L
	
	##### Fetching the CRLs  #####
	##############################
	elif module == "get_CRLs":
		if top < 1 or top > 10:
			print ('usage: crl_crawling.py -m <module> -a <argument>')
			sys.exit()
		# Open database connection
		db = MySQLdb.connect("localhost","root","","CRL", charset='utf8' )
		# prepare a cursor object using cursor() method
		cursor = db.cursor()
		# get the CRL URI
		try:
			sql = '''SELECT crl_uri_id, crl_uri FROM crls_uri WHERE top = %d;''' % top
			#sql = "SELECT * FROM crls_uri;"
			cursor.execute(sql)
			L = cursor.fetchall()
			db.close()
		except Exception as ex:
			print ("Error fetching the CRLs URIs")
			print (ex.args)
			sys.exit()
		dir_path = "/Users/malmeshekah/Documents/obser/CRLs_100k_%d" % top
		print ("We have to fetch %d CRLs" % (len(L)))
		get_CRLs(dir_path, L, top)		
		del L
	
	##### Getting the Certificates and the Connections #####
	########################################################
	elif module == "get_certs_connecs":
		if top < 1 or top > 10:
			print ('usage: crl_crawling.py -m <module> -a <argument>')
			sys.exit()
		L = list()
		with open('/Users/malmeshekah/Documents/SSL_Certs/data/top-100k_%d.csv' % top, 'rb') as csvf:
			csvreader = csv.reader(csvf)
			for csvrow in csvreader:
				L.append(csvrow[1])
			csvf.close()
		print ("Global List size %d" % len(L))
		jobs = []
		cert_dir = "/Users/malmeshekah/Documents/obser/CERTs_100k_%d" % top
		connec_dir = "/Users/malmeshekah/Documents/obser/CONNECs_100k_%d" % top
		for i in range(100):
			x = i * 1000
			y = (i+1) * 1000
			L2 = L[x:y]
			p = multiprocessing.Process(target=get_certs_connces, args=(cert_dir, connec_dir, L2,))
			jobs.append(p)
			p.start()
			del L2
		del L
	
	##### Doing everything - Getting the Certificates and the Connections, parsing the certificates, #####
	#####	parsing the connections and getting the CRLs and saving them in the DB			 #####
	######################################################################################################
	elif module == "ALL":
		if top < 1 or top > 10:
			print ('usage: crl_crawling.py -m <module> -a <argument>')
			sys.exit()
		pid = subprocess.Popen("python crl_crawling.py -m get_certs_connecs -a %d" % top, shell=True)
		pid.wait()
		pid = subprocess.Popen("python crl_crawling.py -m parse_certs_from_files -a %d" % top, shell=True)
		pid.wait()
		pid = subprocess.Popen("python crl_crawling.py -m parse_connecs -a %d" % top, shell=True)
		pid.wait()
		pid = subprocess.Popen("python crl_crawling.py -m get_CRLs -a %d" % top, shell=True)
		pid.wait()
	
	##### Doing everything - Getting the Certificates and the Connections, parsing the certificates, #####
	#####	parsing the connections and getting the CRLs and saving them in the DB			 #####
	######################################################################################################
	elif module == "ALL_with_chain":
		if top < 1 or top > 10:
			print ('usage: crl_crawling.py -m <module> -a <argument>')
			sys.exit()
		pid = subprocess.Popen("python crl_crawling.py -m get_connecs -a %d" % top, shell=True)
		pid.wait()
		pid = subprocess.Popen("python crl_crawling.py -m parse_certs_from_connecs -a %d" % top, shell=True)
		pid.wait()
		pid = subprocess.Popen("python crl_crawling.py -m get_CRLs -a %d" % top, shell=True)
		pid.wait()
	
	##### Manually checking something  #####
	########################################
	elif module == "one_thing":
		dir_path = "/Users/malmeshekah/Documents/obser/CONNECs_100k_%d" % top
		L = list()
		L.append("1c-bitrix.ru.txt")
		print ("We have to parse %d connections blob" % (len(L)))
		parse_connecs(dir_path, L, top)
		del L
	else:
		print ("usage: only [ALL, get_certs, parse_certs_from_files, get_connecs, parse_connecs, get_CRLs, get_certs_connecs] modules are supported")


###########################
##### Setting up main #####
###########################

if __name__ == "__main__":
	main(sys.argv[1:])