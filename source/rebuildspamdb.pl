#!/usr/bin/perl

# perl antispam smtp proxy
# (c) John Hanna, John Calvi, Robert Orso, AJ 2004 under the terms of the GPL
# (c) 2006 Przemyslaw Czerkas <przemekc@poczta.onet.pl>

# Rebuilds bayesian spam database
# - updated July 2004 for simple proxy support.

$version='1.2.0';
$modversion=' beta 0';

use bytes; # get rid of anoying 'Malformed UTF-8' messages

# load from command line if specified
if ($ARGV[0]) {
 $base=$ARGV[0];
} else {
 # the last one is the one used if all else fails
 foreach ('.','assp','/usr/local/assp','/home/assp','/usr/assp','/assp','.') {
  $base=$_;
  last if -e "$base/assp.cfg";
 }
}

sub includeFile {
 my $file=shift;
 my $myver=$version;
 require "$base/$file";
 if ($version ne $myver) {
  my $msg="file version mismatch: '$base/$file' ($version)";
  mlog(0,$msg);
  die ucfirst($msg);
 }
}

includeFile('lib/config.pl');
includeFile('lib/lib.pl');

detectModules();
configLoad();
configInit();
configInitRE();
configInitUpdate();

# data for DayOfWeek function
#my %Months=(Jan,1,Feb,2,Mar,3,Apr,4,May,5,Jun,6,Jul,7,Aug,8,Sep,9,Oct,10,Nov,11,Dec,12);
#my %Month=(1,0,2,3,3,2,4,5,5,0,6,3,7,5,8,1,9,4,10,6,11,2,12,4,);
#my %Weekday=(0,'srdSUN',1,'srdMON',2,'srdTUE',3,'srdWED',4,'srdTHU',5,'srdFRI',6,'srdSAT',);

getmaxtick("$base/data/rebuild");

$spamObject=tie(%spam,orderedtie,"$base/spamtmp") if $RamSaver;
$WhitelistObject=tie %Whitelist,orderedtie,"$base/$whitelistdb" unless $KeepWhitelistedSpam;

$starttime=time;

# add(isspam,filename,weight)
# read the corrections
my @files;
print "Analyzing $correctedspam\n";
opendir(DIR,"$base/$correctedspam");
@files=readdir DIR;
closedir(DIR);
foreach my $f (@files) {add(1,"$base/$correctedspam/$f",2,\&spamHash);}
&tick;
print "\n\n";

print "Analyzing $correctednotspam\n";
opendir(DIR,"$base/$correctednotspam");
@files=readdir DIR;
closedir(DIR);
foreach my $f (@files) {add(0,"$base/$correctednotspam/$f",4,\&hamHash);}
&tick;
print "\n\n";

# read spam database
print "Analyzing $spamlog\n";
opendir(DIR,"$base/$spamlog");
@files=readdir DIR;
closedir(DIR);
foreach my $f (@files) {add(1,"$base/$spamlog/$f",1,\&checkspam);}
#for $n (0 .. 4000) {add(1,"spam/$n",1,\&checkspam)};
&tick;

print "\n\n";
# read non-spam database
print "Analyzing $notspamlog\n";
opendir(DIR,"$base/$notspamlog");
@files=readdir DIR;
closedir(DIR);
foreach my $f (@files) {add(0,"$base/$notspamlog/$f",1,\&checkham);}
#for $n (0 .. 4000) {add(0,"notspam/$n",1,\&checkspam)};
&tick;

print "\n\n";

# update stats
$norm= $HamWordCount? $SpamWordCount/$HamWordCount: 1;
print "Found $SpamWordCount spam words, $HamWordCount non-spam words.\nGenerating weighted keys...\n";
printf "norm=%.4f\n",$norm;
$unknowns=0; $unknownt=0;

open(F,'>',"$base/$spamdb.tmp") or die "Couldn't open '$base/$spamdb.tmp': $!\n";
binmode F;
print F "\n";

if ($spamObject) {
 $spamObject->flush();
 open(I,'<',"$base/spamtmp");
 local $/="\n";
 while (<I>) {
  ($_,$s,$t)=/(.*)\002(\d+) (\d+)/;
  $t=($t-$s)*$norm+$s; # normalize t
  if ($t < 5) {
   #$unknowns+=$s; $unknownt+=$t;
   next;
  }
  # if token represents all spam or all ham then square its value
  if ($s==$t || $s==0) {
   $s=$s*$s; $t=$t*$t;
  }
  $v=(1+$s)/($t+2);
  $v=sprintf("%.7f",$v); $v='0.9999999' if $v >= 1; $v='0.0000001' if $v<=0;
  print F "$_\002$v\n" if abs($v-.5) > .09;
  &tick if ($Tick++ & 0x3f)==0;
 }
 close F;
} else {
 while (my ($k,$v)=each(%spam)) {
  ($s,$t)=split(' ',$v);
  $t=($t-$s)*$norm+$s; # normalize t
  if ($t < 5) {
   #$unknowns+=$s; $unknownt+=$t;
   next;
  }
  # if token represents all spam or all ham then square its value
  if ($s==$t || $s==0) {
   $s=$s*$s; $t=$t*$t;
  }
  $v=(1+$s)/($t+2);
  $v=sprintf("%.7f",$v); $v='0.9999999' if $v >= 1; $v='0.0000001' if $v<=0;
  push(@result,"$k\002$v\n") if abs($v-.5) > .09;
  &tick if ($Tick++ & 0x3f)==0;
 }
 print "Saving rebuilt SPAM database\n";
 undef %spam; # free some memory
 for (sort @result) { print F $_; }
 close F;
}
#printf "unk=($unknowns/$unknownt)=%.7f\n", $unknowns/$unknownt;
backupFile("$base/$spamdb");
rename("$base/$spamdb.tmp","$base/$spamdb") || print "Couldn't rename '$base/$spamdb.tmp' to '$base/$spamdb': $!\n";

# create helo blacklist
open(F,'>',"$base/$spamdb.helo.tmp") || print "Couldn't open '$base/$spamdb.helo.tmp': $!\n";
binmode F;
print F "\n";
while (my ($k,$v)=each(%Helo)) {
 push(@Helo,"$k\0021\n") if $v->[1]/($v->[0]+$v->[1]+.1) > .98;
}
print F sort @Helo;
close F;
undef @Helo; undef %Helo;
backupFile("$base/$spamdb.helo");
rename("$base/$spamdb.helo.tmp","$base/$spamdb.helo");

if (rand()< .05) {
 # rarely, let's clean the whitelist of old entries
 $t=time - 24*3600*$MaxWhitelistDays;
 print "Cleaning whitelist\n";

 if (open(F,'<',"$base/$whitelistdb") && open(O,'>',"$base/$whitelistdb.tmp")) {
  binmode F;
  binmode O;
  local $/="\n";
  <F>; print O "\n";
  while (<F>) {
   my ($a,$rec)=split("\002",$_);
   my ($added,$updated)=split("\003",$rec);
   next if $t>$added || length($a)>60;
   print O;
  }
  close F; close O;
  backupFile("$base/$whitelistdb");
  rename("$base/$whitelistdb.tmp","$base/$whitelistdb");
 }

 if (open(F,'<',"$base/goodhosts") && open(O,'>',"$base/goodhosts.tmp")) {
  binmode F;
  binmode O;
  $t=time - 24*3600*20;
  local $/="\n";
  <F>; print O "\n";
  while (<F>) {
   my ($a,$time)=split("\002",$_);
   next if $time > 99999999 && $t > $time;
   print O;
  }
  close F; close O;
  unlink("$base/goodhosts.bak");
  rename("$base/goodhosts","$base/goodhosts.bak");
  rename("$base/goodhosts.tmp","$base/goodhosts");
 }
}

putmaxtick("$base/data/rebuild");
printf "\ntotal time processing=%d second(s)\n",time-$starttime;
if ($spamObject) {unlink("$base/spamtmp");}

uploadgreylist() unless $noGreyListUpload;

sub mlog { print "$_[1]\n";}
sub spamHash { $SpamHash{hash($_[1])}=''; }

sub hamHash { $HamHash{hash($_[1])}=''; }

sub checkspam {
 my $h;
 #if (whitelisted($_[1])) {print "wl: $_[1]\n\n"; return 1;}
 if (defined($HamHash{$h=hash($_[1])}) || whitelisted($_[1])) {
  # we've found a message in the spam database that is the same as one in the corrected Ham group
  my $fn=shift;
  # delete it
  #print "$fn is spam match\n'$h' -> $HT{$h}\n";
  #$fn2=$fn; $fn2=~s/spam/spam2/;
  #rename($fn,$fn2);
  unlink($fn);
  return 1;
 }
 0;
}

sub whitelisted {
 return 0 if $KeepWhitelistedSpam;
 my $m=shift;
 # test against expression to recognize whitelisted mail
 return 1 if $whiteRE && $m=~/$whiteRE/iso;
 # we should test whitere against "clean"ed mail, but I don't want to waste the cpu time
 $m=~s/\015\012\015\012.*/\015\012/s; # remove body
 while ($m=~/([^:<>,;"'\(\)\s\[\]]+\@[^<>,;"'\(\)\s\?\[\]]+\.[^<>,;"'\(\)\s\?\[\]]+)/gi) {
  return 1 if $Whitelist{lc $1};
 }
 0;
}

sub checkham {
 my $h;
 if (defined($SpamHash{$h=hash($_[1])})) {
  # we've found a message in the ham database that is the same as one in the corrected spam group
  my $fn=shift;
  # delete it
  #print "$fn is ham match\n'$h' -> $HT{$h}\n";
  #$fn2=$fn; $fn2=~s/spam/spam2/;
  #rename($fn,$fn2);
  unlink($fn);
  return 1;
 }
 0;
}

sub get {
 my ($fn,$sub)=@_;
 open(F,'<',$fn) or return '';
 binmode F;
 my $m;
 read(F,$m,$MaxRebuildBytes);
 close F;
 return '' if $sub->($fn,$m);
 if ($spamObject && $GetCount++>500) {
  #print "flushing\n";
  $spamObject->flush();
  $GetCount=0;
 }
 $m;
}

sub add {
 #print "+" if $Counter++ % 100 ==0;
 &tick if ($Tick++ & 0x3f)==0;
 my ($spam,$fn,$factor,$sub)=@_;
 #print "$fn <$spam> [$factor]\n";
 return if -d $fn;
 my ($lt,$t,$nt);
 local $_=get($fn,$sub);
 return unless $_; # use $$sub to identify and remove spam or ham that matches corrected items
 my ($helo)=$_=~/helo=(.*?)\)/i;
 $Helo{lc $helo}->[$spam]+=$factor;
 $_=clean($_);
 while (/([-\$A-Za-z0-9\'\.!\240-\377]+)/g) {
  next if length($1)>20 || length($1)<2;
  $nt=lc $1; $nt=~s/[,.']+$//; $nt=~s/!!!+/!!/g; $nt=~s/--+/-/g;
  next unless $nt;
  $lt=$t; $t=$nt;
  next unless length($lt)>1 || ($lt && length($t)>1);

  if ($spam) {
   $SpamWordCount+=$factor;
  } else {
   $HamWordCount+=$factor;
  }

  #$spam{$t}+=$factor if $spam;
  #$tot{$t}+=$factor;
  #$spam{"$lt $t"}+=$factor if $spam;
  #$tot{"$lt $t"}+=$factor;

  my ($sfac,$tfac)=split(' ',$spam{"$lt $t"});
  $sfac+=$spam ? $factor : 0;
  $tfac+=$factor;
  $spam{"$lt $t"}="$sfac $tfac";
 }
}

sub dayofweek {
 # this is mercilessly hacked from John Von Essen's Date::Day
 my ($d, $m, $y)=$_[0]=~/(\S+) +(\S+) +(\S+)/;
 $y+=2000;
 $m=$Months{$m};
 if ($m <= 2) { $y--; }
 my $wday = (($d+$Month{$m}+$y+(int($y/4))-(int($y/100))+(int($y/400)))%7);
 return $Weekday{$wday};
}

sub hash {
 # creates a $len length hash of $msg
 my $msg=shift;
 my $len=20;
 my ($sub)=$msg=~/^$HeaderAllCRLFRe*Subject$HeaderSepRe($HeaderValueRe)/io;
 # strip header
 $msg=~s/.*?\015\012\015\012//s;
 my $hash=substr($sub,0,20).substr($msg,0,260);
 my @a=(0 .. 94);
 my $c=0;
 for my $n (0 .. length($hash)) {
  $c=($a[$c]+$c+ord(substr($hash,$n,1))) % 95;
  my $n2=$n % 95;
  @a[$n2,$c]=@a[$c,$n2];
 }
 for my $n (0 .. length($hash)) {
  $c=($a[$c]+$c+ord(substr($hash,$n,1))) % 95;
  my $n2=$n % 95;
  @a[$n2,$c]=@a[$c,$n2];
 }
 my $r='';
 $c=0;
 for my $n (@a) {
  $r.=chr($n+32);
  last if ++$c > $len;
 }
 #$HT{$r}=$hash;
 $r;
}

sub tick {
  my $stars=(70 * $Tick / $MaxTick); $stars=70 if $stars > 70;
  $stars='*' x $stars;
  print "$Tick $stars \r";
}
sub getmaxtick {
  if (open(F,'<',"$_[0].mt")) {
   $MaxTick = <F>;
   close F;
   $MaxTick=~y/0-9//cd;
   $MaxTick+=0;
  }
  $MaxTick=1000000 unless $MaxTick>1000;
  print "mt=$MaxTick\n";
}
sub putmaxtick {
  open(F,'>',"$_[0].mt");
  print F $Tick;
  close F;
}

sub uploadgreylist {
 use IO::Socket;
 my ($day,$gooddays);
 $day=localtime(); $day=~s/^... (...) +(\d+) (\S+) ..(..)/$1-$2-$4/; $gooddays.="$day|";
 $day=localtime(time-24*3600); $day=~s/^... (...) +(\d+) (\S+) ..(..)/$1-$2-$4/; $gooddays.="$day|";
 $day=localtime(time-48*3600); $day=~s/^... (...) +(\d+) (\S+) ..(..)/$1-$2-$4/; $gooddays.="$day|";
 $day=localtime(time-72*3600); $day=~s/^... (...) +(\d+) (\S+) ..(..)/$1-$2-$4/; $gooddays.="$day";
 my %locals=(127,1,10,1,'192.168',1,'169.254',1);
 for (16 .. 31) {$locals{"172.$_"}=1}
 my (%m,$stop);
 my @logs=sortLogs($logfile);
 while (@logs && !$stop) {
  $stop=1;
  if (open(F,shift(@logs))) {
   local $/="\n";
   while (<F>) {
    my ($date,$ip,$i1,$i2,$m);
    next unless ($date,$ip,$i1,$i2,$m)=/($gooddays) \S+ ((\d+)\.(\d+)\.\d+)\.\d+ .* to: \S+ (.*)/io;
    next if $locals{$i1} || $locals{"$i1.$i2"};
    # count only 'terminal' lines
    next if $m=~/because (?:testmode|spamlover)/i;
    if ($m=~/ spam|failed|bad attachment |scripting|bomb|virus|malformed|oversized|not srs signed|spam trap|invalid|blacklisted/i) {
     $m{$ip}++;
     # print "bad: $ip $m\n";
    } elsif ($m=~/local|whitelisted|message ok|noprocessing/i) {
     $m{$ip}++;
     $ok{$ip}++;
     # print "ok: $ip $m\n";
    }
    $stop=0;
   }
   close F;
  }
 }
 return unless %m;
 for (sort keys %m) {$st.= "$_\001$m{$_}\002$ok{$_}\003";}
 my $peeraddress,$connect;
 if ($proxyserver) {
   print "Uploading Greylist via Proxy: $proxyserver\n";
   $peeraddress = $proxyserver;
   $connect = "POST http://assp.sourceforge.net/cgi-bin/uploadGrey.pl HTTP/1.0";
 } else {
   print "Uploading Greylist via Direct Connection\n";
   $peeraddress = "assp.sourceforge.net:80";
   $connect = "POST /cgi-bin/uploadGrey.pl HTTP/1.1
Host: assp.sourceforge.net";
 }
 my $s=new IO::Socket::INET(Proto=>'tcp',PeerAddr=>$peeraddress,Timeout=>2);
 if ($s) {
  my $len=length($st);
  $connect.="
Content-Type: application/x-www-form-urlencoded
Content-Length: $len

$st";
  print $s $connect;
  $s->close();
  print "uploaded $len bytes\n";
 } else {
  print "Couldn't connect to assp.sourceforge.net to upload greylist\n";
 }
}
