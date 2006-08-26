#!/usr/bin/perl

# perl antispam smtp proxy
# (c) John Hanna, John Calvi, Robert Orso, AJ 2004 under the terms of the GPL
# (c) 2006 Przemyslaw Czerkas <przemekc@poczta.onet.pl>

$version='1.2.0';
$modversion=' beta 0';

use bytes; # get rid of anoying 'Malformed UTF-8' messages

# Email address components
$EmailAdrRe="[^()<>@,;:\\\"\\[\\]\000-\040]+";
$EmailDomainRe='\w[\w\.\-]*\.\w+';

# Header components
$HeaderCRLFRe='\015\012';
$HeaderNameCharRe='[\041-\071\073-\176]'; # RFC2822 section 2.2 (strict)
$HeaderNameRe=$HeaderNameCharRe.'+';
$HeaderSepRe=':[ \t]?'; # allow RFC822 compliant headers (without WS after the colon)
$HeaderValueCharRe='[\001-\011\013\014\016-\377]'; # RFC2822 section 2.2.1 (loosen -- allow 8-bit characters)
$HeaderValueRe=$HeaderValueCharRe.'*(?:'.$HeaderCRLFRe.'[ \t]+'.$HeaderValueCharRe.'*)*';
$HeaderValueNgRe=$HeaderValueCharRe.'*?(?:'.$HeaderCRLFRe.'[ \t]+'.$HeaderValueCharRe.'*)*?'; # non-greedy

# Header compounds
$HeaderNameSepRe=$HeaderNameRe.$HeaderSepRe;
$HeaderNameSepValueRe=$HeaderNameSepRe.$HeaderValueRe;
$HeaderNameSepValueNgRe=$HeaderNameSepRe.$HeaderValueNgRe; # non-greedy
$HeaderNameSepValueCRLFRe=$HeaderNameSepValueRe.$HeaderCRLFRe;
$HeaderNameSepValueNgCRLFRe=$HeaderNameSepValueNgRe.$HeaderCRLFRe;
$HeaderSepValueRe=$HeaderSepRe.$HeaderValueRe;
$HeaderSepValueNgRe=$HeaderSepRe.$HeaderValueNgRe;
$HeaderSepValueCRLFRe=$HeaderSepValueRe.$HeaderCRLFRe;
$HeaderSepValueNgCRLFRe=$HeaderSepValueNgRe.$HeaderCRLFRe;
$HeaderValueCRLFRe=$HeaderValueRe.$HeaderCRLFRe;
$HeaderValueNgCRLFRe=$HeaderValueNgRe.$HeaderCRLFRe;
$HeaderAllRe=$HeaderNameSepValueRe;
$HeaderAllNgRe=$HeaderNameSepValueNgRe;
$HeaderAllCRLFRe='(?:'.$HeaderAllRe.$HeaderCRLFRe.')';
$HeaderAllNgCRLFRe='(?:'.$HeaderAllNgRe.$HeaderCRLFRe.')';

# IP Address representations
$IPQuadSectRE='(?:0([0-7]+)|0x([0-9a-f]+)|(\d+))';
$IPQuadSectDotRE='(?:'.$IPQuadSectRE.'\.)';
$IPQuadRE=$IPQuadSectDotRE.'?'.$IPQuadSectDotRE.'?'.$IPQuadSectDotRE.'?'.$IPQuadSectRE;

# URI components
$URICharRe='(?:[=%][0-9a-f]{2}|\#\&\d{1,3};?|[0-9a-z\-\_\.\@]|\=(?:\015?\012|\015))';

# collection identifiers
@Collections=('correctedspam',
              'correctednotspam',
              'notspamlog',
              'incomingOkMail',
              'spamlog',
              'viruslog');

# detect installed modules
sub detectModules {
 $CanUseLDAP=eval('use Net::LDAP; 1'); # Net LDAP module installed
 $CanUseAddress=eval('use Email::Valid; 1'); # Email Valid module installed
 $CanUseDNS=eval('use Net::DNS; 1'); # Net DNS module installed - required for SPF, RBL, URIBL & Tooltips
 $AvailSPF=eval('use Mail::SPF::Query; 1'); # Mail SPF module installed
 $CanUseSPF=$AvailSPF && $CanUseDNS; # SPF and dependancies installed
 $CanUseURIBL=$CanUseRWL=$CanUseRBL=$CanUseDNS; # URIBL, RWL, RBL and dependancies installed
 $AvailSRS=eval('use Mail::SRS; 1'); # Mail SRS module installed
 $CanUseSRS=$AvailSRS;
 $AvailZlib=eval('use Compress::Zlib; 1'); # Zlib module installed
 $CanUseHTTPCompression=$AvailZlib;
 $AvailMD5=eval('use Digest::MD5; 1'); # Digest MD5 module installed
 $CanUseMD5Keys=$AvailMD5;
 $AvailReadBackwards=eval('use File::ReadBackwards; 1'); # ReadBackwards module installed;
 $CanSearchLogs=$AvailReadBackwards;
 $AvailHiRes=eval('use Time::HiRes; 1'); # Time::HiRes module installed;
 $CanStatCPU=$AvailHiRes;
 $AvailIPRegexp=eval('use Net::IP::Match::Regexp; 1'); # Net::IP::Match::Regexp module installed
 $CanMatchCIDR=$AvailIPRegexp;
}

#####################################################################################
#                Bayesian SPAM Detection

# clean up source email
sub clean {
 my $m=shift;
 # clear out interfering headers
 $m=~s/^(?:Return-Path|Delivered-To|In-Reply-To|Message-ID|References|X-Assp-$HeaderNameRe|X-Intended-For)$HeaderSepValueCRLFRe//gimo;
 # parse helo
 my ($helo)=$m=~/helo=([^)]+)\)/i;
 $helo=join(' hlo ',$helo=~/(\w+)/g) if length($helo)>19; # if the helo string is long, break it up
 $helo="hlo $helo";
 # received's may interfere with rcpt parsing, clear them out now
 $m=~s/^Received$HeaderSepValueCRLFRe//gimo;
 # parse rcpt's
 my $rcpt='rcpt '.join(' rcpt ',$m=~/($EmailAdrRe\@$EmailDomainRe)/g);
 # mark the subject
 my ($ssub)=$m=~/^$HeaderAllCRLFRe*Subject$HeaderSepRe($HeaderValueRe)/io;
 $ssub=decodeMimeWords($ssub);
 # remove the spamSubject
 $ssub=~s/$spamSubjectTagRE //gi if $spamSubject;
 # remove the ccHamSubject
 $ssub=~s/$ccHamSubjectTagRE //gi if $ccHamSubject;
 # remove the ccSpamSubject
 $ssub=~s/$ccSpamSubjectTagRE //gi if $ccSpamSubject;
 # remove the ccBlockedSubject
 $ssub=~s/$ccBlockedSubjectTagRE //gi if $ccBlockedSubject;
 $ssub=fixsub($ssub);
 # strip out mime separators
 my @bounds;
 push(@bounds,quotemeta($1)) while $m=~/^Content-Type$HeaderSepRe(?:$HeaderValueRe)boundary=\"(.*?)\"/gimo;
 if (@bounds) {
  my $bounds=join('|',@bounds);
  $m=~s/^--(?:$bounds)(?:--)?(?:\015\012)?//gim;
 }
 # remove header lines
 $m=~s/^$HeaderAllCRLFRe*//o;
 # replace &#ddd encoding
 $m=~s/&#(\d{1,3});?/chr($1)/ge;
 # replace base64 encoding
 $m=~s/\015\012([a-zA-Z0-9+\/=]{40,}\015\012[a-zA-Z0-9+\/=\015\012]+)/"\015\012".base64decode($1)/gse;
 # clean up quoted-printable references
 $m=~s/=\015\012//g;
 $m=~s/=([0-9a-fA-F]{2})/pack('C',hex($1))/gie;
 # replace url encoding
 $m=~s/%([0-9a-fA-F]{2})/pack('C',hex($1))/ge;
 # clean up &nbsp; and &amp;
 $m=~s/&nbsp;?/ /gi;
 $m=~s/&amp;?/and/gi;
 $m=~s/(\d),(\d)/$1$2/g;
 $m=~s/ *\015\012/\015\012/g;
 $m=~s/\015\012\015\012\015\012\015\012(?:\015\012)+/\015\012blines blines\015\012/g;
 # clean up html stuff
 $m=~s/<script.*?>\s*(?:<!\S*)?/ jscripttag jscripttag /gi;
 while ($m=~s/(\w+)(<[^>]*>)((?:<[^>]*>)*\w+)/$2$1$3/g){} # move html out of words
 $m=~s/<(?:[biu]|strong)>/ boldifytext boldifytext /gi;
 # remove some tags that are not informative
 $m=~s/<\/?(?:p|br|div|t[dr])[^>]*>/\015\012/gi;
 $m=~s/<\/(?:[biu]|font|strong)>//gi;
 $m=~s/<\/?(?:html|meta|head|body|span|o)[^>]*>//gi;
 $m=~s/(<a\s[^>]*>)(.*?)(<\s*\/a\s*>)/$1.fixlinktext($2).$3/gise;
 $m=~s/<\s*\/a\s*>//gi;
 # treat titles like subjects
 $m=~s/<title[^>]*>(.*?)<\/title>/fixsub($1)/gie;
 # remove style sheets
 $m=~s/<style[^>]*>.*?<\/style>//gis;
 # remove html comments
 $m=~s/<!.*?-->//gs;
 $m=~s/<![^>]*>//g;
 # look for random words
 $m=~s/[ a-z0-9][ghjklmnpqrstvwxz_]{2}[bcdfghjklmnpqrstvwxz_0-9]{3}\S*/ randword randword /gi;
 # look for linked images
 $m=~s/(<a[^>]*>[^<]*<img)/ linkedimage linkedimage $1/gis;
 $m=~s/<[^>]*href\s*=\s*("[^"]*"|\S*)/fixhref($1)/gise;
 $m=~s/https?:\/\/(\S*)/fixhref($1)/gise;
 $m=~s/(\S+\@\S*\.\w{2,3})\b/fixhref($1)/ge;
 # remove headers from message body
 $m=~s/^$HeaderAllCRLFRe//gmo;
 # clean up whitespaces
 $m=~s/^\s*//gm;
 $m=~s/ {2,}/ /g;
 return "$helo\015\012$rcpt\015\012$ssub\015\012$m";
}

sub fixhref {
 my $t=shift;
 $t=~s/(\w+)\.?/ href $1 /g;
 return $t;
}

sub fixlinktext {
 my $t=shift;
 $t=~s/(\w+)/ atxt $1 /g;
 return $t;
}

sub fixsub {
 my $s=shift;
 $s=~s/ {3,}/ lotsaspaces /g;
 $s=~s/(\S+)/ssub $1/g;
 return $s;
}

#####################################################################################
#                helper functions

sub sgn {
 return ($_[0]>0)-($_[0]<0);
}

sub makeDirs {
 my ($b,$ds)=@_;
 foreach my $d (split(/[\\\/]/,$ds)) {
  mkdir "$b/$d",0700;
  $b.="/$d";
 }
}

sub removeDirs {
 my ($b,$ds)=@_;
 foreach my $d (reverse split(/[\\\/]/,$ds)) {
  rmdir "$b/$ds";
  $ds=~s/[\\\/]\Q$d\E$//i;
 }
}

sub samePaths {
 my ($p1,$p2)=@_;
 my $rp1=resolvePath($p1);
 my $rp2=resolvePath($p2);
 return $rp1 eq $rp2;
}

sub resolvePath {
 my $p=shift;
 my @ret;
 foreach my $c (split(/[\\\/]/,$p)) {
  if ($c eq '.') {
   next;
  } elsif ($c eq '..') {
   pop(@ret) if @ret;
   next;
  } elsif ($c) {
   push(@ret,lc $c);
  }
 }
 return ($p=~/^[\\\/]/ ? '/' : '').join('/',@ret);
}

sub dirEmpty {
 my $dir=shift;
 my $cnt;
 if (opendir(DIR,$dir)) {
  0 while defined readdir(DIR) && ++$cnt<3;
  closedir(DIR);
 }
 return $cnt<3;
}

sub backupFile {
 return unless $BackupCopies>0;
 my $f=shift;
 my $bf=$f; $bf=~s/.*[\\\/]|/bak\//;
 my $i=$BackupCopies-1;
 unlink("$base/$bf.$i");
 for (; $i>0; $i--) { rename("$base/$bf.".($i-1),"$base/$bf.$i"); }
 rename($f,"$base/$bf.0");
}

sub sortLogs {
 my $logs=shift;
 my @logs;
 if ($LogRotateCopies) {
  @logs=map{$_->[0]} sort{$a->[1]<=>$b->[1]} map{[$_,/(\d*)$/]} <$base/$logs*>; # S-T
 } else {
  $logs=~s/(.*[\\\/]|)/$1*/;
  @logs=reverse sort <$base/$logs>;
 }
 return @logs;
}

sub formatMethod {
 my $res;
 if ($_[2]==0) {
  $res=int($_[0]/$_[1]);
  $_[0]-=$res*$_[1]; # modulus on floats
 } elsif ($_[2]==1) {
  if ($_[0]>=$_[1]) {
   $res=sprintf("%.1f",$_[0]/$_[1]);
   $_[0]=0;
  }
 }
 return $res;
}

sub formatTimeInterval {
 my ($interval,$method)=@_;
 my ($res,$i);
 $res.=$i.'d ' if $i=formatMethod($interval,86400,$method);
 $res.=$i.'h ' if $i=formatMethod($interval,3600,$method);
 $res.=$i.'m ' if $i=formatMethod($interval,60,$method);
 if ($interval<1 && $interval>0) {
  $interval*=1e6; # magnify
  $res.=$i.'ms ' if $i=formatMethod($interval,1e3,$method);
  $res.=$i.'us ' if $i=formatMethod($interval,1,$method);
  $interval=0;
 }
 if ($interval || !defined $res) {
  if ($method==0) {
   $res.=$interval.'s ';
  } elsif ($method==1) {
   $res.=sprintf("%.1fs ",$interval);
  }
 }
 $res=~s/\s$//;
 return $res;
}

sub formatDataSize {
 my ($size,$method)=@_;
 my ($res,$s);
 $res.=$s.'TB ' if $s=formatMethod($size,1099511627776,$method);
 $res.=$s.'GB ' if $s=formatMethod($size,1073741824,$method);
 $res.=$s.'MB ' if $s=formatMethod($size,1048576,$method);
 $res.=$s.'kB ' if $s=formatMethod($size,1024,$method);
 if ($size || !defined $res) {
  if ($method==0) {
   $res.=$size.'B ';
  } elsif ($method==1) {
   $res.=sprintf("%.1fB ",$size);
  }
 }
 $res=~s/\s$//;
 return $res;
}

sub unformatTimeInterval {
 my ($interval,$default)=@_;
 my @a=split(' ',$interval);
 my $res=0;
 foreach my $i (@a) {
  my ($i,$mult)=$i=~/^(.*?) ?([smhd]?)$/;
  $mult||=$default||'s'; # default to seconds
  if ($mult eq 's') {
   $res+=$i;
  } elsif ($mult eq 'm') {
   $res+=$i*60;
  } elsif ($mult eq 'h') {
   $res+=$i*3600;
  } elsif ($mult eq 'd') {
   $res+=$i*86400;
  }
 }
 return $res;
}

sub unformatDataSize {
 my ($size,$default)=@_;
 my @a=split(' ',$size);
 my $res=0;
 foreach my $s (@a) {
  my ($s,$mult)=$s=~/^(.*?) ?(B|kB|MB|GB|TB)?$/;
  $mult||=$default||'B'; # default to bytes
  if ($mult eq 'B') {
   $res+=$s;
  } elsif ($mult eq 'kB') {
   $res+=$s*1024;
  } elsif ($mult eq 'MB') {
   $res+=$s*1048576;
  } elsif ($mult eq 'GB') {
   $res+=$s*1073741824;
  } elsif ($mult eq 'TB') {
   $res+=$s*1099511627776;
  }
 }
 return $res;
}

sub decodeMimeWord {
 my ($charset,$encoding,$text)=@_;
 # ignore charset
 my $s;
 if (lc $encoding eq 'b') {
  $text=base64decode($text);
 } elsif (lc $encoding eq 'q') {
  $text=~s/_/\x20/g; # RFC 1522, Q rule 2
  $text=~s/=([\da-fA-F]{2})/pack('C', hex($1))/ge; # RFC 1522, Q rule 1
 }
 return $text;
}

sub decodeMimeWords {
 my $s=shift;
 headerUnwrap($s);
 $s=~s/=\?([^?]*)\?(b|q)\?([^?]+)\?=/decodeMimeWord($1,$2,$3)/gie;
 return $s;
}

sub base64decode {
 my $str=shift;
 my $res;
 $str=~tr|A-Za-z0-9+/||cd;
 $str=~tr|A-Za-z0-9+/| -_|;
 while ($str=~/(.{1,60})/gs) {
  my $len=chr(32+length($1)*3/4);
  $res.=unpack('u', $len.$1);
 }
 return $res;
}

# wrap long header (in place)
sub headerWrap {
 $_[0]=~s/(?:([^\015\012]{60,75}?;|[^\015\012]{60,75}) ) {0,5}(?=[^\015\012]{10,})/$1\015\012\t/g;
}

# unwrap long header (in place)
sub headerUnwrap {
 $_[0]=~s/\015\012[ \t]+//g;
}

sub needEs {
 my ($count,$text,$es,$noes)=@_;
 return $count . $text . ($count==1 ? $noes : $es);
}

# wrap long log lines
sub logWrap {
 my ($line,$column,$indent)=@_;
 my $wraps=$column+11; # $wraps must be >= $indent, or 'while ...' loops infinitely
 my $wrape=$wraps+15;
 # wrap anchors are: space;-,.:= (but not &lt; &gt;)
 # matches are greedy to minimize number of line breaks
 # not a danger code as long as $wraps >= $indent
 while ($line=~s/(?:([^\n]{$wraps,$wrape}) |([^\n]{$wraps,$wrape}(?<![lg]t);)|([^\n]{$wraps,$wrape}[-,.:=])) {0,5}(?=[^\n]{5,}$)/$1$2$3\n$indent/) {};
 return $line;
}

# check if email address matches RE
sub matchSL {
 my ($a,$re)=@_;
 my $reRE=${$MakeSLRE{$re}};
 return 0 unless $reRE;
 return $a=~/$reRE/;
}

# check if IP address matches RE
sub matchIP {
 my ($ip,$re)=@_;
 my $reRE=${$MakeIPRE{$re}};
 return 0 unless $ip && $reRE;
 my $ret;
 local $^R;
 use re 'eval';
 if ($CanMatchCIDR) {
  ('4'.unpack 'B32', pack 'C4', split /\./xms, $ip)=~/$reRE/xms;
 } else {
  $ip=~/$reRE/xms;
 }
 $ret=$^R;
 return $ret if $re eq 'noLog';
 mlog(0,"IP $ip".($ret==1 ? '' : " ($ret)")." matches $re") if $IPMatchLog && !matchIP($ip,'noLog') && $ret;
 return $ret;
}

# check if email address or IP address matches RE
sub matchSLIP {
 my ($a,$ip,$re)=@_;
 return matchSL($a,$re) || matchIP($ip,$re);
}

# check if RateLimit event is enabled
sub RLIBTEventEnabled {
 my $name=shift;
 $name=~s/^RLIBT(.*)/$1/;
 return 0 if !$RateLimitClient && $name=~/^(?:clientHeloValidated|clientHeloUnchecked|clientHeloForged|clientHeloBlacklisted|clientHeloMismatch|clientHeloSpam)$/;
 return 0 if !$RateLimitSender && $name=~/^(?:senderValidatedLocal|senderUncheckedLocal|senderWhitelisted|senderValidatedRemote|senderUncheckedRemote|senderUnprocessed|senderForged|senderBombLocal|senderNoMX|senderBombRemote)$/;
 return 0 if !$RateLimitRcpt && $name=~/^(?:rcptValidated|rcptUnchecked|rcptSpamLover|rcptWhitelisted|rcptNotWhitelisted|rcptUnprocessed|rcptDelayed|rcptDelayedLate|rcptDelayedExpired|rcptEmbargoed|rcptSpamBucket)$/;
 return 0 if !$RateLimitPassed && $name=~/^(?:msgAnyHam|msgAnyPassedSpam|noprocessing|locals|whites|reds|bhams|spamlover|testspams)$/;
 return 0 if !$RateLimitBlocked && $name=~/^(?:msgAnyBlockedSpam|helolisted|senderfails|blacklisted|msgNoSRSBounce|spambucket|spffails|rblfails|malformed|uriblfails|bombs|scripts|viri|viridetected|bspams)$/;
 return 0 if !$RateLimitEmailInterface && $name=~/^(?:rcptReportSpam|rcptReportHam|rcptReportWhitelistAdd|rcptReportWhitelistRemove|rcptReportRedlistAdd|rcptReportRedlistRemove)$/;
 return 0 if !$RateLimitMisc && $name=~/^(?:rcptNonexistent|msgNoRcpt|rcptRelayRejected|msgMaxErrors|msgEarlytalker|msgDelayed|msgAborted)$/;
 return 1;
}

# check if Av option is enabled
sub AvOptionEnabled {
 my $name=shift;
 return 0 if !$AvUseClamAV && $name=~/^(?:AvDestination|Avmaxtime)$/;
 return 0 if $AvUseClamAV && $name=~/^(?:AvPath|AvDbs|AVBytes)$/;
 return 1;
}

# compare version strings
sub vercmp {
 my ($ver1,$ver2)=@_;
 my ($d11,$d12,$d13,$s11,$d14,$s12)=$ver1=~/^\s*(\d+)\.(\d+)\.(\d+)\s*(\D*?)\s*(\d*)\s*(\D*?)\s*$/;
 my ($d21,$d22,$d23,$s21,$d24,$s22)=$ver2=~/^\s*(\d+)\.(\d+)\.(\d+)\s*(\D*?)\s*(\d*)\s*(\D*?)\s*$/;
 my $v1=$d11*10000+$d12*100+$d13;
 my $v2=$d21*10000+$d22*100+$d23;
 # compare versions
 if ($v1==$v2) {
  $s11=lc $s11;
  $s21=lc $s21;
  # favor final release
  my $m1=(!$s11 || $s11=~/^final/ || ($s11=~/^release/ && $s11!~/candidate/));
  my $m2=(!$s21 || $s21=~/^final/ || ($s21=~/^release/ && $s21!~/candidate/));
  if ($m1) {
   if ($m2) {
    return 0;
   } else {
    return 1;
   }
  } elsif ($m2) {
   return -1;
  } else {
   # favor release candidate
   $m1=($s11=~/candidate/ || $s11=~/^rc/);
   $m2=($s21=~/candidate/ || $s21=~/^rc/);
   if ($m1) {
    if ($m2) {
     # favor empty modversion
     if (!$d14) {
      if (!$d24) {
       return 0;
      } else {
       return 1;
      }
     } elsif (!$d24) {
      return -1;
     } else {
      # compare modversions
      if ($d14==$d24) {
       if ($s12 eq $s22) {
        return 0;
       } elsif ($s12 gt $s22) {
        return 1;
       } else {
        return -1;
       }
      } elsif ($d14>$d24) {
       return 1;
      } else {
       return -1;
      }
     }
    } else {
     return 1;
    }
   } elsif ($m2) {
    return -1;
   } else {
    # compare modstrings
    $s11='beta' if $s11 eq 'b'; # 'b' itself means 'beta'
    $s21='beta' if $s21 eq 'b'; # 'b' itself means 'beta'
    if ($s11 eq $s21) {
     # favor empty modversion
     if (!$d14) {
      if (!$d24) {
       return 0;
      } else {
       return 1;
      }
     } elsif (!$d24) {
      return -1;
     } else {
      # compare modversions
      if ($d14==$d24) {
       if ($s12 eq $s22) {
        return 0;
       } elsif ($s12 gt $s22) {
        return 1;
       } else {
        return -1;
       }
      } elsif ($d14>$d24) {
       return 1;
      } else {
       return -1;
      }
     }
    } elsif ($s11 gt $s21) {
     return 1;
    } else {
     return -1;
    }
   }
  }
 } elsif ($v1>$v2) {
  return 1;
 } else {
  return -1;
 }
}

#####################################################################################
#                orderedtie
{
package orderedtie;
# This is a tied value that caches lookups from a sorted file; \n separates records,
# \002 separates the key from the value. After main::OrderedTieHashSize lookups the cache is
# cleared. This give us most of the speed of the hash without the huge memory overhead of storing
# the entire hash and should be totally portable. Picking the best value for n requires some
# tuning. A \n is required to start the file.

# if you're updating entries it behoves you to call flush every so often to make sure that your
# changes are saved. This also frees the memory used to remember updated values.

# for my purposes a value of undef and a nonexistant key are the same

# Obviously if your keys or values contain \n or \002 it will totally goof things up.


sub TIEHASH {
 my ($c,$fn)=@_;
 my $self={
  fn => $fn,
  age => mtime($fn),
  cnt => 0,
  cache => {},
  updated => {},
  ptr => 1,
 };
 bless $self, $c;
 return $self;
}

sub DESTROY {
 $_[0]->flush();
}

sub UNTIE {
 $_[0]->flush();
}

sub mtime {
 my @s=stat($_[0]);
 $s[9];
}

sub flush {
 my $this=shift;
 return unless %{$this->{updated}};
 my $f=$this->{fn};
 open(O,">$f.tmp") or return undef;
 binmode(O);
 open(I,"<$f") || print O "\n";
 binmode(I);
 local $/="\n";
 my @l=(sort keys %{$this->{updated}});
 my ($k,$d,$r,$v);
 while ($r=<I>) {
  ($k,$d)=split("\002",$r);
  while (@l && $l[0] lt $k) {
   $v=$this->{updated}{$l[0]};
   print O "$l[0]\002$v\n" if $v;
   shift(@l);
  }
  if ($l[0] eq $k) {
   $v=$this->{updated}{$l[0]};
   print O "$l[0]\002$v\n" if $v;
   shift(@l);
  } else {
   print O $r;
  }
 }
 while (@l) {
  $v=$this->{updated}{$l[0]};
  print O "$l[0]\002$v\n" if $v;
  shift(@l);
 }
 close I; close O; unlink($f); rename("$f.tmp", $f);
 $this->{updated}={};
}

sub STORE {
 my ($this, $key, $value)=@_;
 $this->{cache}{$key}=$this->{updated}{$key}=$value;
}

sub FETCH {
 my ($this, $key)=@_;
 return $this->{cache}{$key} if exists $this->{cache}{$key};
 $this->resetCache() if ($this->{cnt}++ >$main::OrderedTieHashSize || ($this->{cnt} & 0x1f)==0 && mtime($this->{fn})!=$this->{age});
 return $this->{cache}{$key}=binsearch($this->{fn},$key);
}

sub resetCache {
 my $this=shift;
 $this->{cnt}=0;
 $this->{age}=mtime($this->{fn});
 $this->{cache}={%{$this->{updated}}};
## main::mlog(0,"cache reset ($this->{fn})") if $main::MaintenanceLog;
}

sub binsearch {
 my ($f,$k)=@_;
 open(F,"<$f") or return undef;
 binmode(F);
 my $count=0;
 my $siz=my $h=-s $f;
 $siz-=1024;
 my $l=0;
 my $k0=$k;
 $k=~s/([\[\]\(\)\*\^\!\|\+\.\\\/\?\`\$\@\{\}])/\\$1/g; # make sure there's no re chars unqutoed in the key
 while (1) {
  my $m=(($l+$h)>>1)-1024;
  $m=0 if ($m<0);
  seek(F,$m,0);
  my $d; my $read= read(F,$d,2048);
  if ($d=~/\n$k\002([^\n]*)\n/) {
   close F;
   return $1;
  }
  my ($pre,$first,$last,$post)=$d=~/^(.*?)\n(.*?)\002.*\n(.*?)\002.*?\n(.*?)$/s;
  last unless defined $first;
  if ($k0 gt $first && $k0 lt $last) {
   last;
  }
  if ($k0 lt $first) {
   last if ($m==0);
   $h=$m-1024+length($pre);
   $h=0 if ($h<0);
  }
  if ($k0 gt $last) {
   last if $m>=$siz;
   $l=$m+$read-length($post);
  }
##  if (($count++)>100) {
##   main::mlog(0,"error: $this->{fn} must be repaired ($k0)");
##   last;
##  }
 }
 close F;
 return undef;
}

sub FIRSTKEY {
 $this=shift;
 $this->flush();
 $this->{ptr}=1;
 $this->NEXTKEY();
}

sub NEXTKEY {
 my ($this, $lastkey)=@_;
 local $/="\n";
 open(F,"<$this->{fn}") or return undef;
 binmode(F);
 seek(F,$this->{ptr},0);
 my $r=<F>;
 unless ($r) {
  close F;
  return undef;
 }
 $this->{ptr}=tell F;
 close F;
 my ($k,$v)=$r=~/(.*?)\002(.*?)\n/s;
 if (!exists($this->{cache}{$k}) && $this->{cnt}++ >$main::OrderedTieHashSize) {
  $this->{cnt}=0;
  $this->{cache}={%{$this->{updated}}};
 }
 $this->{cache}{$k}=$v;
 $k;
}

sub EXISTS {
 my ($this, $key)=@_;
 return FETCH($this, $key);
}

sub DELETE {
 my ($this, $key)=@_;
 $this->{cache}{$key}=$this->{updated}{$key}=undef;
}

sub CLEAR {
 my ($this)=@_;
 open(F,">$this->{fn}"); binmode(F); print F "\n"; close F;
 $this->{cache}={};
 $this->{updated}={};
 $this->{cnt}=0;
}
}

1;