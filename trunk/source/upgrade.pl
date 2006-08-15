#!/usr/bin/perl

# perl antispam smtp proxy
# (c) John Hanna, John Calvi, Robert Orso, AJ 2004 under the terms of the GPL

# This is used to clean up some settings and perform an upgrade
# Primarily these are settings that might be absent from assp.cfg
# or settings that are not needed anymore after an upgrade

$version='1.2.0';
$modversion=' beta 0';

use bytes; # get rid of annoying 'Malformed UTF-8' messages

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

configLoad();

# open logfile
if ($Config{logfile}) {
 my ($dir)=$Config{logfile}=~/(.*[\\\/])/;
 makeDirs($base,$dir);
 if (open(LOG,">>$base/$Config{logfile}")) {
  my $oldfh=select(LOG); $|=1; select($oldfh);
 }
 $logfile=$Config{logfile}; # mlog needs $logfile
}

# check config version
if ((my $cmp=vercmp($Config{ConfigVersion},"$version$modversion"))>0) {
 my $msg="config file version is too new ($Config{ConfigVersion}), exiting";
 mlog(0,$msg);
 die ucfirst($msg);
} elsif ($cmp==0) {
 my $msg="config file version is up to date ($Config{ConfigVersion}), exiting";
 mlog(0,$msg);
 die ucfirst($msg);
}

mlog(0,"upgrading to $version$modversion ...");

# for upgrading from earlier than 1.1.1
if (vercmp($Config{ConfigVersion},'1.1.1')<0) {
 if (exists $Config{TestMode}) {
  if ($Config{TestMode}) {
   $Config{baysTestMode}=1;
   $Config{blTestMode}=1;
   $Config{hlTestMode}=1;
   $Config{mfTestMode}=1;
   $Config{sbTestMode}=1;
   $Config{spfTestMode}=1;
   $Config{rblTestMode}=1;
   $Config{srsTestMode}=1;
   $Config{uriblTestMode}=1;
   $Config{malformedTestMode}=1;
  }
  # TestMode is not used in this version
  delete $Config{TestMode};
 }
}

# for upgrading from earlier than 1.1.2 beta 1
if (vercmp($Config{ConfigVersion},'1.1.2 beta 1')<0) {
 delete $Config{noProcessingDomains} if exists $Config{noProcessingDomains};
 delete $Config{showDNSValidation} if exists $Config{showDNSValidation};
 delete $Config{showEmailInterface} if exists $Config{showEmailInterface};
 delete $Config{showFilePaths} if exists $Config{showFilePaths};
 delete $Config{showLogging} if exists $Config{showLogging};
 delete $Config{showNetworkSetup} if exists $Config{showNetworkSetup};
 delete $Config{showOtherSettings} if exists $Config{showOtherSettings};
 delete $Config{showRelaying} if exists $Config{showRelaying};
 delete $Config{showSecurity} if exists $Config{showSecurity};
 delete $Config{showSpamBomb} if exists $Config{showSpamBomb};
 delete $Config{showSpamControl} if exists $Config{showSpamControl};
 delete $Config{showTestModeOptions} if exists $Config{showTestModeOptions};
 delete $Config{showValidateRecipients} if exists $Config{showValidateRecipients};
 delete $Config{showVirusControl} if exists $Config{showVirusControl};
 delete $Config{showWhitelistOptions} if exists $Config{showWhitelistOptions};
 if (exists $Config{ExtensionsToBlock}) {
  $Config{BadAttachL1}=$Config{ExtensionsToBlock};
  # ExtensionsToBlock is not used in this version
  delete $Config{ExtensionsToBlock};
 }
 if (exists $Config{EmailWhitelist}) {
  $Config{EmailWhitelistAdd}=$Config{EmailWhitelist};
  # EmailWhitelist is not used in this version
  delete $Config{EmailWhitelist};
 }
}

# for upgrading from earlier than 1.2.0 beta 0
if (vercmp($Config{ConfigVersion},'1.2.0 beta 0')<0) {
 delete $Config{UseSubjectsAsMaillogNames} if exists $Config{UseSubjectsAsMaillogNames};
 # collection upgrade transition hash
 %Log2Coll=(2=>1, 3=>8, 4=>3, 5=>11, 6=>9, 7=>10);
 if (exists $Config{baysNonSpamLog}) {
  $Config{baysNonSpamColl}=$Log2Coll{$Config{baysNonSpamLog}};
  # baysNonSpamLog is not used in this version
  delete $Config{baysNonSpamLog};
 }
 if (exists $Config{blDomainLog}) {
  $Config{blDomainColl}=$Log2Coll{$Config{blDomainLog}};
  # blDomainLog is not used in this version
  delete $Config{blDomainLog};
 }
 if (exists $Config{spamHeloLog}) {
  $Config{spamHeloColl}=$Log2Coll{$Config{spamHeloLog}};
  # spamHeloLog is not used in this version
  delete $Config{spamHeloLog};
 }
 if (exists $Config{spamBucketLog}) {
  $Config{spamBucketColl}=$Log2Coll{$Config{spamBucketLog}};
  # spamBucketLog is not used in this version
  delete $Config{spamBucketLog};
 }
 if (exists $Config{SPFFailLog}) {
  $Config{SPFFailColl}=$Log2Coll{$Config{SPFFailLog}};
  # SPFFailLog is not used in this version
  delete $Config{SPFFailLog};
 }
 if (exists $Config{RBLFailLog}) {
  $Config{RBLFailColl}=$Log2Coll{$Config{RBLFailLog}};
  # RBLFailLog is not used in this version
  delete $Config{RBLFailLog};
 }
 if (exists $Config{SRSFailLog}) {
  $Config{SRSFailColl}=$Log2Coll{$Config{SRSFailLog}};
  # SRSFailLog is not used in this version
  delete $Config{SRSFailLog};
 }
 if (exists $Config{spamBombLog}) {
  $Config{spamBombColl}=$Log2Coll{$Config{spamBombLog}};
  # spamBombLog is not used in this version
  delete $Config{spamBombLog};
 }
 if (exists $Config{scriptLog}) {
  $Config{scriptColl}=$Log2Coll{$Config{scriptLog}};
  # scriptLog is not used in this version
  delete $Config{scriptLog};
 }
 if (exists $Config{wlAttachLog}) {
  $Config{wlAttachColl}=$Log2Coll{$Config{wlAttachLog}};
  # wlAttachLog is not used in this version
  delete $Config{wlAttachLog};
 }
 if (exists $Config{npAttachLog}) {
  $Config{npAttachColl}=$Log2Coll{$Config{npAttachLog}};
  # npAttachLog is not used in this version
  delete $Config{npAttachLog};
 }
 if (exists $Config{extAttachLog}) {
  $Config{extAttachColl}=$Log2Coll{$Config{extAttachLog}};
  # extAttachLog is not used in this version
  delete $Config{extAttachLog};
 }
 if (exists $Config{baysSpamLog}) {
  $Config{baysSpamColl}=$Log2Coll{$Config{baysSpamLog}};
  # baysSpamLog is not used in this version
  delete $Config{baysSpamLog};
 }
 if (exists $Config{sendAllSpam}) {
  $Config{ccBlocked}=$Config{ccSpam}=$Config{ccHam}=$Config{sendAllSpam};
  # sendAllSpam is not used in this version
  delete $Config{sendAllSpam};
 }
 if (exists $Config{UpdateWhitelist}) {
  $Config{MaintenanceInterval}=$Config{UpdateWhitelist};
  # UpdateWhitelist is not used in this version
  delete $Config{UpdateWhitelist};
 }
 if (exists $Config{CleanDelayDBInterval}) {
  # CleanDelayDBInterval is not used in this version
  delete $Config{CleanDelayDBInterval};
 }
 if (exists $Config{ccAddresses}) {
  $Config{ccFilter}=$Config{ccAddresses};
  # ccAddresses is not used in this version
  delete $Config{ccAddresses};
 }
 if (exists $Config{ForceEarlyRBLCheck}) {
  $Config{RBLPosition}=3 if $Config{ForceEarlyRBLCheck};
  # ForceEarlyRBLCheck is not used in this version
  delete $Config{ForceEarlyRBLCheck};
 }
 if (exists $Config{DelaySL}) {
  # DelaySL is not used in this version
  delete $Config{DelaySL};
 }
 if (exists $Config{noSRS}) {
  $Config{noSRSBounce}=$Config{noSRS};
  # noSRS changes meaning in this version
  $Config{noSRS}='';
 }
 if (exists $Config{SessionLog}) {
  $Config{SessionLimitLog}=$Config{SessionLog};
  # SessionLog is not used in this version
  delete $Config{SessionLog};
 }
 if (exists $Config{RBLNonFatal}) {
  $Config{RBLError}=~s/^5/4/ if $Config{RBLNonFatal};
  # RBLNonFatal is not used in this version
  delete $Config{RBLNonFatal};
 }
 if (exists $Config{noHeloBlacklist}) {
  $Config{HeloBlacklist}=$Config{noHeloBlacklist} ? '' : 1;
  # noHeloBlacklist is not used in this version
  delete $Config{noHeloBlacklist};
 }
 if (exists $Config{DoFakedLocalHelo}) {
  $Config{HeloForged}=$Config{DoFakedLocalHelo};
  # DoFakedLocalHelo is not used in this version
  delete $Config{DoFakedLocalHelo};
 }
 if (exists $Config{NoHaiku}) {
  $Config{NoHaikuCorrection}=$Config{NoHaiku};
  $Config{NoHaikuWhitelist}=$Config{NoHaiku};
  $Config{NoHaikuRedlist}=$Config{NoHaiku};
  # NoHaiku is not used in this version
  delete $Config{NoHaiku};
 }
 if (exists $Config{heloBlacklistIgnore}) {
  # heloBlacklistIgnore is not used in this version
  delete $Config{heloBlacklistIgnore};
 }
 if (exists $Config{defaultLocalHost}) {
  $Config{defaultLocalDomain}=$Config{defaultLocalHost};
  # defaultLocalHost is not used in this version
  delete $Config{defaultLocalHost};
 }
 if (exists $Config{denySMTPConnectionsFrom}) {
  $Config{denySMTPConnections}=$Config{denySMTPConnectionsFrom};
  # denySMTPConnectionsFrom is not used in this version
  delete $Config{denySMTPConnectionsFrom};
 }
 if (exists $Config{allowAdminConnectionsFrom}) {
  $Config{allowAdminConnections}=$Config{allowAdminConnectionsFrom};
  # allowAdminConnectionsFrom is not used in this version
  delete $Config{allowAdminConnectionsFrom};
 }
 if (exists $Config{DoNoValidLocalSender}) {
  $Config{SenderForged}=$Config{DoNoValidLocalSender};
  # DoNoValidLocalSender is not used in this version
  delete $Config{DoNoValidLocalSender};
 }
 if (exists $Config{ValidateLog}) {
  $Config{RecipientValLog}=$Config{ValidateLog};
  # ValidateLog is not used in this version
  delete $Config{ValidateLog};
 }
 if (exists $Config{NoValidRecipient}) {
  $Config{InvalidRecipientError}=$Config{NoValidRecipient};
  # NoValidRecipient is not used in this version
  delete $Config{NoValidRecipient};
 }


 if (exists $Config{HeloWL}) {
  if ($Config{HeloWL}) {
   $Config{HeloExtra}|=2;
  } else {
   $Config{HeloExtra}&=255-2;
  }
  # HeloWL is not used in this version
  delete $Config{HeloWL};
 }
 if (exists $Config{SenderWL}) {
  if ($Config{SenderWL}) {
   $Config{SenderExtra}|=2;
  } else {
   $Config{SenderExtra}&=255-2;
  }
  # SenderWL is not used in this version
  delete $Config{SenderWL};
 }
 if (exists $Config{SPFWL}) {
  if ($Config{SPFWL}) {
   $Config{SPFExtra}|=2;
  } else {
   $Config{SPFExtra}&=255-2;
  }
  # SPFWL is not used in this version
  delete $Config{SPFWL};
 }
 if (exists $Config{RBLWL}) {
  if ($Config{RBLWL}) {
   $Config{RBLExtra}|=2;
  } else {
   $Config{RBLExtra}&=255-2;
  }
  # RBLWL is not used in this version
  delete $Config{RBLWL};
 }
 if (exists $Config{MsgVerifyWL}) {
  if ($Config{MsgVerifyWL}) {
   $Config{MsgVerifyExtra}|=2;
  } else {
   $Config{MsgVerifyExtra}&=255-2;
  }
  # MsgVerifyWL is not used in this version
  delete $Config{MsgVerifyWL};
 }
 if (exists $Config{URIBLWL}) {
  if ($Config{URIBLWL}) {
   $Config{URIBLExtra}|=2;
  } else {
   $Config{URIBLExtra}&=255-2;
  }
  # URIBLWL is not used in this version
  delete $Config{URIBLWL};
 }
 if (exists $Config{RateLimitWL}) {
  if ($Config{RateLimitWL}) {
   $Config{RateLimitExtra}|=2;
  } else {
   $Config{RateLimitExtra}&=255-2;
  }
  # RateLimitWL is not used in this version
  delete $Config{RateLimitWL};
 }


 # fix error codes
 $Config{AttachmentError}=~s/^5\d/55/;
 $Config{AvError}=~s/^5\d/55/;
 $Config{SpamError}=~s/^5\d/55/;
 $Config{bombError}=~s/^\d\d\d/550/;
 $Config{scriptError}=~s/^\d\d\d/550/;
 $Config{NoRelaying}=~s/^5\d/55/;
 $Config{InvalidRecipientError}=~s/^(\d)\d/$1\065/; # \065 = '5'
 mlog(0,'config settings fixed');
 my ($f,$nf);
 # rename backup files
 my %baks=('assp.cfg.bak.bak'=>'assp.cfg.1','assp.cfg.bak'=>'assp.cfg.0',
           "$Config{spamdb}.bak"=>"$Config{spamdb}.0","$Config{spamdb}.helo.bak"=>"$Config{spamdb}.helo.0",
           "$Config{whitelistdb}.bak"=>"$Config{whitelistdb}.0");
 while (my ($b,$v)=each(%baks)) {
  $f="$base/$b";
  $nf="bak/$v";
  if (-e $f && !samePaths($f,"$base/$nf")) {
   my ($dir)=$nf=~/(.*[\\\/])/;
   makeDirs($base,$dir);
   unlink("$base/$nf");
   if (rename($f,"$base/$nf")) {
    mlog(0,"backup file renamed/moved from '$f' to '$base/$nf'");
   } else {
    mlog(0,"failed to rename/move backup file from '$f' to '$base/$nf': $!");
   }
  }
 }
 # rename corpus folders
 my %colls=('correctedspam'=>'errors/spam','correctednotspam'=>'errors/notspam','notspamlog'=>'notspam',
            'incomingOkMail'=>'okmail','spamlog'=>'spam','viruslog'=>'virii');
 while (my ($c,$v)=each(%colls)) {
  my $dc="corpus/$v";
  if ($Config{$c} && $dc && !samePaths("$base/$Config{$c}","$base/$dc")) {
   makeDirs($base,$dc);
   rmdir("$base/$dc"); # remove last dir
   if (rename("$base/$Config{$c}","$base/$dc")) {
    removeDirs($base,$Config{$c});
    mlog(0,"collection \$$c renamed/moved from '$base/$Config{$c}' to '$base/$dc'");
    $Config{$c}=$dc;
   } else {
    mlog(0,"failed to rename/move collection \$$c from '$base/$Config{$c}' to '$base/$dc': $!");
   }
  }
 }
 # move lists files
 while (my ($l,$v)=each(%Config)) {
  if ($v=~/^ *file: *(.+)/i && $1) {
   # the option list is actually saved in a file.
   $f=$1; $f="$base/$f" if $f!~/^\Q$base\E/i;
   $nf=$f; $nf=~s/.*[\\\/]|/data\/lists\//;
   if (-e $f && !samePaths($f,"$base/$nf")) {
    my ($dir)=$nf=~/(.*[\\\/])/;
    makeDirs($base,$dir);
    unlink("$base/$nf");
    if (rename($f,"$base/$nf")) {
     mlog(0,"list file \$$l moved from '$f' to '$base/$nf'");
     $Config{$l}="file:$nf";
    } else {
     mlog(0,"failed to move list file \$$l from '$f' to '$base/$nf': $!");
    }
   }
  }
 }
 # move report files
 my @reps=('spamreport.txt','notspamreport.txt','whitereport.txt',
           'whiteremovereport.txt','redreport.txt','redremovereport.txt');
 foreach my $r (@reps) {
  $f="$base/$r";
  $nf=$f; $nf=~s/.*[\\\/]|/data\/reports\//;
  if (-e $f && !samePaths($f,"$base/$nf")) {
   my ($dir)=$nf=~/(.*[\\\/])/;
   makeDirs($base,$dir);
   unlink("$base/$nf");
   if (rename($f,"$base/$nf")) {
    mlog(0,"report file moved from '$f' to '$base/$nf'");
   } else {
    mlog(0,"failed to move report file from '$f' to '$base/$nf': $!");
   }
  }
 }
 # move database files
 my @dbs=("$Config{spamdb}.helo","$Config{delaydb}.white");
 foreach my $d (@dbs) {
  if ($d!~/^\./) {
   $f="$base/$d";
   $nf=$f; $nf=~s/.*[\\\/]|/data\//;
   if (-e $f && !samePaths($f,"$base/$nf")) {
    my ($dir)=$nf=~/(.*[\\\/])/;
    makeDirs($base,$dir);
    unlink("$base/$nf");
    if (rename($f,"$base/$nf")) {
     mlog(0,"database file moved from '$f' to '$base/$nf'");
    } else {
     mlog(0,"failed to move database file from '$f' to '$base/$nf': $!");
    }
   }
  }
 }
 @dbs=('spamdb','whitelistdb','redlistdb','dnsbl','greylist','delaydb');
 foreach my $d (@dbs) {
  if ($Config{$d}) {
   $f="$base/$Config{$d}";
   $nf=$f; $nf=~s/.*[\\\/]|/data\//;
   if (-e $f && !samePaths($f,"$base/$nf")) {
    my ($dir)=$nf=~/(.*[\\\/])/;
    makeDirs($base,$dir);
    unlink("$base/$nf");
    if (rename($f,"$base/$nf")) {
     mlog(0,"database file \$$d moved from '$f' to '$base/$nf'");
     $Config{$d}=$nf;
    } else {
     mlog(0,"failed to move database file \$$d from '$f' to '$base/$nf': $!");
    }
   }
  }
 }
 $f="$base/asspstats.sav";
 $nf=$f; $nf=~s/.*[\\\/]|/data\//;
 if (-e $f && !samePaths($f,"$base/$nf")) {
  my ($dir)=$nf=~/(.*[\\\/])/;
  makeDirs($base,$dir);
  unlink("$base/$nf");
  if (rename($f,"$base/$nf")) {
   mlog(0,"statistics file moved from '$f' to '$base/$nf'");
  } else {
   mlog(0,"failed to move statistics file from '$f' to '$base/$nf': $!");
  }
 }
 # remove superfluous files, new location is 'docs' subdirectory
 my @docs=('ASSP Documentation.htm','Regular Expression Tutorial.htm','changelog.txt',
           'rc/readme.txt','rc/assp.dat','rc/start.dat','rc/stop.dat');
 if (-e "$base/$docs[0]") {
  foreach $f (@docs) {
   unlink("$base/$f");
   my ($dir)=$f=~/(.*[\\\/])/;
   removeDirs($base,$dir);
  }
  mlog(0,"documentation files moved from '$base/' to '$base/docs'");
 }
 # move log files
 my $alllogs=$Config{logfile}; $alllogs=~s/(.*[\\\/]|)/$1*/;
 if ($Config{logfile} && !samePaths($1,'logs')) {
  close LOG;
  makeDirs($base,'logs');
  foreach $f (<$base/$alllogs>) {
   $nf=$f; $nf=~s/.*[\\\/]|/logs\//;
   unlink("$base/$nf");
   rename($f,"$base/$nf");
  }
  $Config{logfile}=~s/.*[\\\/]|/logs\//;
  # reopen logfile
  if ($Config{logfile}) {
   if (open(LOG,">>$base/$Config{logfile}")) {
    my $oldfh=select(LOG); $|=1; select($oldfh);
   }
   $logfile=$Config{logfile}; # mlog needs $logfile
  }
  $alllogs=~s/(?:[\\\/]|)\*.*$//;
  mlog(0,"log files moved from '$base/$alllogs' to '$base/logs'");
 }
 # move2num corpus files
 my @colls=('notspamlog','incomingOkMail','spamlog','viruslog');
 my $ext=$Config{maillogExt};
 my $max=$Config{MaxFiles};
 foreach my $c (@colls) {
  if ($Config{$c}) {
   opendir(DIR,"$base/$Config{$c}");
   my @files=readdir DIR;
   closedir(DIR);
   my $i=1;
   foreach my $f (@files) {
    next if -d $f;
    next if $f=~/^(\d+)$ext$/i && $1<$max;
    while ($i<$max && -s "$base/$Config{$c}/$i$ext") {$i++;}
    $i=int($max*rand()) if $i==$max;
    my $nf="$i$ext";
    unlink("$base/$Config{$c}/$nf");
    unless (rename("$base/$Config{$c}/$f","$base/$Config{$c}/$nf")) {
     mlog(0,"failed to rename collection \$$c file from '$base/$Config{$c}/$f' to '$base/$Config{$c}/$nf': $!");
    }
   }
   mlog(0,"collection \$$c files renamed to numbers");
  }
 }
 # remove move2num.pl script
 if (-e "$base/move2num.pl") {
  unlink("$base/move2num.pl");
  mlog(0,"move2num.pl script removed from '$base/'");
 }
 # convert corpus files, this will take some time ...
 foreach my $c (@Collections) {
  if ($Config{$c}) {
   opendir(DIR,"$base/$Config{$c}");
   my @files=readdir DIR;
   closedir(DIR);
   my $cnt=@files;
   my $done=0;
   my $ltime=time;
   foreach my $f (@files) {
    next if -d $f;
    if (open(F,"<$base/$Config{$c}/$f")) {
     binmode(F);
     my ($h,$b);
     undef $/;
     $h=<F>;
     close F;
     # split message into header and body
     ($h,$b)=$h=~/^(?:(.*?)(?:\015\015|\015\012\015\012|\012\012|\012\015)|)(.*)$/s;
     # fix malformed header but keep 'artifacts'
     my ($good,$all)=(0)x2;
     $good++ while $h=~/\015\012/g;
     $all++ while $h=~/\015?\012|\015/g;
     $h=~s/\015?\012|\015/\015\012/g if $all>2*$good;
     $h.="\015\012" if $h;
     $b=~s/\015?\012|\015/\015\012/g;
     if (open(F,">$base/$Config{$c}/$f.tmp")) {
      binmode(F);
      print F "$h\015\012$b";
      close F;
      unlink("$base/$Config{$c}/$f");
      unless (rename("$base/$Config{$c}/$f.tmp","$base/$Config{$c}/$f")) {
       mlog(0,"failed to rename collection \$$c temporary file from '$base/$Config{$c}/$f.tmp' to '$base/$Config{$c}/$f': $!");
      }
     } else {
      mlog(0,"failed to open collection \$$c temporary file '$base/$Config{$c}/$f.tmp' for writing: $!");
     }
    } else {
     mlog(0,"failed to open collection \$$c file '$base/$Config{$c}/$f' for reading: $!");
    }
    $done++;
    my $time=time;
    if ($time-$ltime>60) {
     $ltime=$time;
     mlog(0,sprintf("converted %.0f%% of files in collection \$$c",100*$done/$cnt)) if $cnt;
    }
   }
   mlog(0,"collection \$$c files converted");
  }
 }
# # pre-cache corpus files, this will take some time ...
# $CorpusObject=tie %Corpus,orderedtie,"$base/$Config{corpusdb}";
# foreach my $c (@Collections) {
#  if ($Config{$c}) {
#   opendir(DIR,"$base/$Config{$c}");
#   my @files=readdir DIR;
#   closedir(DIR);
#   foreach my $f (@files) {
#    corpusDetails("$Config{$c}/$f",1);
#   }
#   mlog(0,"collection \$$c pre-cached");
#  $CorpusObject->flush() if $CorpusObject;
#  }
# }
}

# save current version in config
$Config{ConfigVersion}="$version$modversion";
mlog(0,'upgrade finished');
# close logfile
close LOG if $Config{logfile};

# save configuration file
$BackupCopies=3; # needed in ConfigSave
configSave();

sub mlog{
 my ($fh,$message)=@_;
 my $m=localtime();
 $m=~s/^... (...) +(\d+) (\S+) ..(..)/$1-$2-$4 $3 /;
 my $indent=' ' x length($m); # calculate indent
 $m.="$0: ".ucfirst($message)."\n";
 print logWrap($m,40,$indent) unless $silent;
 print LOG $m if $logfile;
}
