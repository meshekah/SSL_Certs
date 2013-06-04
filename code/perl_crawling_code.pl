#! /usr/bin/perl

use strict;
use warnings;
use Encode;
use FileHandle;
use IPC::Open2;
use LWP::Simple;
use DBI;


########################################################
# 				Get the Certificate
########################################################
my $line;											# To hold the response lines.
my $cert;											# To hold the certificate.
my $cert_found = 0;									# True if the certificate was found.
my @certs;											# To hold the certificates in chain.
my $protocol;										# Hold the connection protocol.
my $cipher;											# Holds the connection cipher.

my $pid = open2(*Reader, *Writer,					# Running the openssl command to get
	"openssl s_client -connect mozilla.com:443 "	#	the certificate
	. " -showcerts");	
print Writer "end_connection";						# Closing the connection to the site.
close Write;
while (<Reader>) {
	$line = $_;
	#print $line;
	
	##### Processing the certificate #####	
	if ($cert_found == 1) {							# Save the certificate.
		$cert = $cert . $line;
	}
	
	if ($line =~ m/BEGIN CERTIFICATE/i) {			# Certificate found
		$cert_found = 1;
		$cert = $line;
	}
	
	if ($line =~ m/END CERTIFICATE/i) {				# The certificate is saved.
		$cert_found = 0;
		push(@certs,$cert);							
	}
	
	##### Processing the Connection #####
	if ($line =~ /^.*Protocol\s*:\s*(.*)$/) {
		$protocol = $1;
	}
	
	if ($line =~ /^.*Cipher\s*:\s*(.*)$/) {
		$cipher = $1;
	}
}
close Reader;


########################################################
# Read the certificate in plain text and get the CRL URI
########################################################
my @CRLs_URI;										# Saving all the CRLs URI.
my $serial;											# Holds the certificate serial number.
my $sig_alg;										# Holds the signature algorithm.
my $subject;										# Holds the subject information.
my $issuer;											# Holds the issuer information.
my $key_leng;										# Holds the key length.
my $ocsp;											# Holds the OCSP URI.

foreach $cert (@certs) {
	$pid = open2(*Reader, *Writer, "openssl x509 -text ");
	print Writer "$cert \n";
	close Writer;

	while (<Reader>) {
		$line = $_;
		if ($line =~ /^.*URI:\s*(http.*crl).*$/) {	# Get the CRL URI
			push(@CRLs_URI, $1);
 		}
 		elsif ($line =~ /^.*Serial Number\s*:\s*(\d*)\s*.*$/) { # Get the cert serial.
 			$serial = $1;
 		}
 		elsif ($line =~ /^.*Signature Algorithm\s*:\s*(\w*).*$/) { # Get the sig Alg.
 			$sig_alg = $1;
 		}
 		elsif ($line =~ /^.*Issuer\s*:\s*(.*)$/) {	# Get the subject information.
 			$issuer = $1;
 		}
 		elsif ($line =~ /^.*Subject\s*:\s*(.*)$/) {	# Get the subject information.
 			$subject = $1;
 		}
 		elsif ($line =~ /^.*Public Key\s*:\s*\((\d*).*$/) {	# get the public key length.
 			$key_leng = $1;
 		}
 		elsif ($line =~ /^.*OCSP.*URI\s*:\s*(http.*)$/) {	# get the OCSP URI.
 			$ocsp = $1;
 		}
	}
	close Reader;
}


########################################################
# 				Get the CRL Objects
########################################################
my $crl_URI;										# Hold an individual CRL URI.
my @CRLs;											# Holds all the CRL objects.
my $crl;
my $i = 0;											# Loop variable.

foreach $crl_URI (@CRLs_URI) {
	$crl = get($crl_URI) or die 'Unable to get CRL';
	push(@CRLs, $crl);
	open FILE, ">", "CRLs/crl_file".$i.".crl" or die $!;
	print FILE $crl;
	close FILE;
	$i = $i + 1;
}

########################################################
# 			Convert the CRL objects into text
########################################################
my $last_update;
my $next_update;

foreach $crl (@CRLs) {
	$pid = open2(*Reader, *Writer, "openssl crl -text -inform DER\n");
	print Writer "$crl \n";
	close Writer;

	while (<Reader>) {
		$line = $_;
		print $line;
 		if ($line =~ /^.*Issuer\s*:\s*(.*)$/) {	# Get the subject information.
 			$issuer = $1;
 		}
 		elsif ($line =~ /^.*Last Update\s*:\s*(.*)$/) {
 			$last_update = $1;
 		}
 		elsif ($line =~ /^.*Next Update\s*:\s*(.*)$/) {
 			$next_update = $1;
 		}
		elsif ($line =~ /^.*CRL Number\s*:\s*(.*)$/) {
 			$serial = $1;
 			print $1;
 		}
	}
	close Reader;
}