#!/usr/bin/perl -w
#** Copyright Mozilla

use Digest::SHA2;
use MIME::Base64;
use strict;

my $depth = 0;

##returns the digest digest of the pkinfo of a cert given a $datainfo hash
sub get_sha1fp {
    my $data = shift;
    my %data_info;

    parse_asn1( $data, \%data_info, 0 );

    my $has_optional = 0;
    my $first_item   = $data_info{0}{0};
    if ( $first_item->{'type'} == 160 ) {
        $has_optional++;
    }

    my $subject_key_cert_info = $data_info{0}{ 5 + $has_optional };
    my $offset = $subject_key_cert_info->{'offset'};
    my $length = $subject_key_cert_info->{'length_total'};
    my $header_len = $subject_key_cert_info->{'length_total'} - $subject_key_cert_info->{'length'};
    my $bytes = unpack( "x" . $offset . " a" . $length, $data );
    my $sha = new Digest::SHA2 256;
    $sha->add($bytes);

    return $sha;
}

##this is as ugly as it can be, but we do not use external libraries
##and gives us access to the raw position of the asn1 struct that
## we need to calculate the fingerprint.
sub parse_asn1 {
    my $data        = shift;
    my $data_info   = shift;
    my $current_pos = shift;
    my %local_data_info;
    my $do_print = 0;
    my $i;
    $depth++;

    $data_info->{'type'} = unpack( "x" . $current_pos . " C1", $data );
    if ( $data_info->{'type'} >= 192 ) {
        die "cannot handle this case tag=" . $data_info->{'type'};
    }
    $data_info->{'offset'} = $current_pos;
    my $length = unpack( "x" . ( $current_pos + 1 ) . " C1", $data );

    if ( $length <= 128 ) {
        $data_info->{'length'}       = $length;
        $data_info->{'length_total'} = $length + 2;
    }
    else {
        #multi-byte depth
        my $length_bytes  = $length - 128;
        my $actual_length = 0;
        for ( $i = 0 ; $i < $length_bytes ; $i++ ) {
            my $read_byte =	unpack( "x" . ( $current_pos + 2 + $i ) . " C1", $data );
            $actual_length += $read_byte * ( 256**( $length_bytes - 1 - $i ) );
        }

        $data_info->{'length'}       = $actual_length;
        $data_info->{'length_total'} = $actual_length + 2 + $length_bytes;
    }

    ##we iterate over sets or sequences
    ##this is a sequence (0x30) or a set (0x31)
    if ( $data_info->{'type'} == 0x30 ) {
        my $processed_length = 0;
        my $header_len = $data_info->{'length_total'} - $data_info->{'length'};
        for ( $i = 0 ; $data_info->{'length'} > $processed_length ; $i++ ) {
            my %local_hash;
            $data_info->{$i} = \%local_hash;
            $processed_length += parse_asn1( $data, \%local_hash, $current_pos + $header_len + $processed_length );
        }
    }
    $depth--;

    return $data_info->{'length_total'};
}

sub main {
    if ($#ARGV != 0 ) {
        print "Usage - Please provide the certificate file name.\n";
        exit;
    }
    open (F, $ARGV[0]) or die "Cannot Open the file";
    my $buf = "";
    while (<F>) {
        if (/-----BEGIN CERTIFICATE-----/) {
            next;
        }
        last if (/-----END CERTIFICATE-----/);
        $buf .= $_;
    }
    my $fp = get_sha1fp( MIME::Base64::decode($buf) );
    print $fp->hexdigest . "\n";
    exit;
}

main();