#!/usr/bin/perl

# perl antispam smtp proxy
# (c) John Hanna, John Calvi, Robert Orso, AJ 2004 under the terms of the GPL
# (c) 2006 Przemyslaw Czerkas <przemekc@poczta.onet.pl>

# ASSP founded and developed to Version 1.0.12 by John Hanna.
# ASSP web interface by AJ.
# ASSP development since 1.0.12 by John Calvi.
# LDAP implementation by Robert Orso.
# Special Thanks for contributions to.....
  # Nigel Barling - SPF & RBL.
  # Mark Pizzolato - SMTP Session Limits.
  # Przemek Czerkas - SRS, Delaying, Searches, HTTP Compression, URIBL, RateLimit, CIDR IP's,
  #                   Corpus Viewer, Tooltips, Simulator
  # Fritz Borgstedt - HELO and Sender Validation

## use Strict;
## use Warnings;

$version='1.2.0';
$modversion=' beta 0'; # appended in version display.

use bytes; # get rid of annoying 'Malformed UTF-8' messages

%SubjectTags=('noprocessing' => 'noprocessing',
              'locals' => 'local',
              'whites' => 'white',
              'reds' => 'red',
              'bhams' => 'bayesian',
              'bspams' => 'bayesian',
              'helolisted' => 'helo',
              'senderfails' => 'sender',
              'blacklisted' => 'black',
              'msgNoSRSBounce' => 'srs',
              'spambucket' => 'trap',
              'spffails' => 'spf',
              'rblfails' => 'rbl',
              'uriblfails' => 'uribl',
              'malformed' => 'malformed',
              'bombs' => 'bomb',
              'scripts' => 'script',
              'viri' => 'attachment',
              'viridetected' => 'virus');

@MyHeaders=('Received-Headers',
            'Delay',
            'Received-SPF',
            'Received-RBL',
            'Received-URIBL',
            'Envelope-From',
            'Whitelisted',
            'Redlisted',
            'Spam-Analysis',
            'Spam-Prob',
            'Spam',
            'Spam-Reason');

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
includeFile('lib/task.pl');
includeFile('lib/web.pl');

# allow override for default web admin port
if ($ARGV[1]=~/^\d+$/) {
 foreach my $c (@Config) {
  if ($c->[0] eq 'webAdminPort' ) {
   $c->[4]=$ARGV[1];
   last;
  }
 }
}

# Notes on general operation & program structure (partially outdated)
# I'm using IO::Select, so don't make any changes that block for long
# as new connections come we create a pair of entries in a hash %Con
# based on the hash of the filehandle, so $Con{$fh} has data for this
# connection. $Con{$fh}->{friend} is the partner socket for the smtp proxy.
# ->{ip} is the ip address of the connecting client
# ->{port} is the port number of the connecting client
# ->{relayok} tells if we can relay mail for this client
# ->{getline} is a pointer to a function that should be called whan a line of input is received for this filehandle
# ->{mailfrom} is the envelope sender (MAIL FROM:<address>)
# ->{outgoing} is a buffer for outgoing socket traffic (see $writable & &sendque)
# ->{rcpt} are the addresses from RCPT TO:<address> (space separated)
# ->{header} and ->{body} is where the header (and eventually the first $MaxBytes bytes) are stored
# ->{myheader} is where we store our header, we merge it with client's header later
# ->{spamfound} is a 3-bits flag used to signal if an email is determined to be spam
# ->{noprocessing} is a 6-bits flag used to signal if an email is not to be processed
# ->{maillength} is the length processed so far (we stop after $MaxBytes bytes)
# ->{coll} is the field used for collecting
# ->{stats} is the field used for statistics
# ->{tag} is the field used for subject tagging
# ->{mlogbuf} is the field used for logging
#
# After connection the {getline} field functions like a state machine
# redirecting input to subsequent handlers
#
# whiteBody -> getLine
#   getBody ->
#     sendError -> (disconnects)
#     getLine -> getHeader ->
#       whiteBody -> getLine
#         sendError -> (disconnects)
#
# getLine looks for MAIL FROM, RCPT TO, RSET
# getHeader looks for a blank line then tests for whitelist / spamaddresses
# getBody looks for the . and calls checkSpam, the Bayesian spam test
# whiteBody waits for . and redirects client to server
# sendError waits for . ignoring data from client (and finishes the maillog)
#
# the server has states like this:
#
# skipok -> reply
#
# skipok traps the 250 ok response from the NOOP Connection from
# reply echos server messages to the client
# reply also looks for a 235 AUTH OK and sets {relayok}=1

use IO::Socket;
use Time::Local;
use IO::File;

main();
# Never reached...(we hope)

#####################################################################################
#                Subroutines

sub main {
 detectModules();
 configLoad();
 configInit();
 configInitRE();
 configInitUpdate();
 configSave();
 if ($logfile && open(LOG,">>$base/$logfile")) {
  my $oldfh=select(LOG); $|=1; select($oldfh);
 }
 if ($slogfile && open(SLOG,">>$base/$slogfile")) {
  my $oldfh=select(SLOG); $|=1; select($oldfh);
 }
 if ($AsAService) {
  eval(<<'EOT');
   use Win32::Daemon;
   mlog(0,'starting as a service');
   Win32::Daemon::StartService();
   # Wait until the service manager is ready for us to continue...
   while (SERVICE_START_PENDING!=Win32::Daemon::State()) { sleep(1); }
   Win32::Daemon::State(SERVICE_RUNNING);

   sub taskServiceCheck {
    return coro(sub{&jump;
     while (1) {
      waitTaskDelay(0,5);
      return cede('L1'); L1:
      if (SERVICE_STOP_PENDING==Win32::Daemon::State()) {
       mlog(0,'service stopping');
       doneAllTasks();
       saveDatabases(1)->();
       Win32::Daemon::State(SERVICE_STOPPED);
       Win32::Daemon::StopService();
       exit;
      }
     }
    });
   }
EOT
  print STDERR "error: $@\n" if $@;
  print LOG "error: $@\n" if $@;
 }
 mlog(0,"ASSP version $version$modversion (Perl $] $^O) initializing");
 initModules();
 initSockets();
 initSignals();
 createPid();
 initDirs(); # changes user/root directory
 openDatabases(1); # force open
 initTasks();
 $shuttingDown=$doShutdown=0;
 $Stats{starttime}=time;
 $Stats{version}="$version$modversion";
 resetStats();
 webRender();
 mlog(0,'starting');
 if ($AsADaemon) {
  fork() && exit;
  close STDOUT;
  close STDERR;
  $silent=1;
 }
 while (doTask()) {
  # main loop
 }
}

sub initModules {
 my $v;
 if ($CanUseLDAP) {
  $v=eval('Net::LDAP->VERSION'); $v=" version $v" if $v;
  mlog(0,"Net::LDAP module$v installed and available");
 } else {
  mlog(0,'Net::LDAP module not installed');
 }
 if ($CanUseDNS) {
  $v=eval('Net::DNS->VERSION'); $v=" version $v" if $v;
  mlog(0,"Net::DNS module$v installed and available");
 } else {
  mlog(0,'Net::DNS module not installed');
 }
 if ($CanUseAddress) {
  $v=eval('Email::Valid->VERSION'); $v=" version $v" if $v;
  mlog(0,"Email::Valid module$v installed and available");
 } else {
  mlog(0,'Email::Valid module not installed');
 }
 if ($CanUseSPF) {
  $v=eval('Mail::SPF::Query->VERSION'); $v=" version $v" if $v;
  mlog(0,"Mail::SPF::Query module$v installed and available");
 } elsif ($AvailSPF) {
  $v=eval('Mail::SPF::Query->VERSION'); $v=" version $v" if $v;
  mlog(0,"Mail::SPF::Query module$v installed but Net::DNS required");
 } else {
  mlog(0,'Mail::SPF::Query module not installed');
 }
 if ($CanUseSRS) {
  $v=eval('Mail::SRS->VERSION'); $v=" version $v" if $v;
  mlog(0,"Mail::SRS module$v installed - Sender Rewriting Scheme available");
 } elsif (!$AvailSRS) {
  mlog(0,'Mail::SRS module not installed - Sender Rewriting Scheme disabled');
 }
 if ($CanUseHTTPCompression) {
  $v=eval('Compress::Zlib->VERSION'); $v=" version $v" if $v;
  mlog(0,"Compress::Zlib module$v installed - HTTP compression available");
 } elsif (!$AvailZlib) {
  mlog(0,'Compress::Zlib module not installed - HTTP compression disabled');
 }
 if ($CanUseMD5Keys) {
  $v=eval('Digest::MD5->VERSION'); $v=" version $v" if $v;
  mlog(0,"Digest::MD5 module$v installed - delaying will use MD5 keys for hashes");
 } elsif (!$AvailMD5) {
  mlog(0,'Digest::MD5 module not installed - delaying will use plain text keys for hashes');
 }
 if ($CanSearchLogs) {
  $v=eval('File::ReadBackwards->VERSION'); $v=" version $v" if $v;
  mlog(0,"File::ReadBackwards module$v installed - searching of log files enabled");
 } elsif (!$AvailReadBackwards) {
  mlog(0,'File::ReadBackwards module not installed - searching of log files disabled');
 }
 if ($CanStatCPU) {
  $v=eval('Time::HiRes->VERSION'); $v=" version $v" if $v;
  mlog(0,"Time::HiRes module$v installed - CPU usage statistics available");
 } elsif (!$AvailHiRes) {
  mlog(0,'Time::HiRes module not installed - CPU usage statistics disabled');
 }
 if ($CanMatchCIDR) {
  $v=eval('Net::IP::Match::Regexp->VERSION'); $v=" version $v" if $v;
  mlog(0,"Net::IP::Match::Regexp module$v installed - IP addresses in RE's can use CIDR notation");
 } elsif (!$AvailIPRegexp) {
  mlog(0,'Net::IP::Match::Regexp module not installed - CIDR notation for IP addresses in RE\'s disabled');
 }
}

# create sockets
sub initSockets {
 mlog(0,"listening for mail connections at $listenPort") if $Lsn=newListen($listenPort);
 mlog(0,"listening for admin connections at $webAdminPort") if $WebSocket=newListen($webAdminPort);
 mlog(0,"listening for additional mail connections at $listenPort2") if $listenPort2 && ($Lsn2=newListen($listenPort2));
 mlog(0,"listening for relay connections at $relayPort") if $relayHost && $relayPort && ($Relay=newListen($relayPort));
}

# signal handlers
sub initSignals {
 $SIG{INT}=sub { mlog(0,'sig INT'); doneAllTasks(); saveDatabases(1)->(); kill 6,$$ if $ENV{windir}; removePid(); exit; };
 $SIG{TERM}=sub { mlog(0,'sig TERM'); doneAllTasks(); saveDatabases(1)->(); removePid(); exit; };
 $SIG{HUP}=sub { mlog(0,'sig HUP'); configReload(); };
 $SIG{PIPE}='IGNORE';
}

sub initDirs {
 # drop privileges/change root directory
 my ($uid,$gid)=getUidGid($runAsUser,$runAsGroup) if $runAsUser || $runAsGroup;
 if ($ChangeRoot) {
  my $chroot;
  eval{$chroot=chroot($ChangeRoot)};
  if ($@) {
   my $msg="request to change root to '$ChangeRoot' failed: $@";
   mlog(0,$msg);
   die ucfirst($msg);
  } elsif (!$chroot) {
   my $msg="request to change root to '$ChangeRoot' did not succeed: $!";
   mlog(0,$msg);
   die ucfirst($msg);
  } else {
   $base=~s/^\Q$ChangeRoot\E//i;
   chdir('/');
   mlog(0,"successfully changed root to '$ChangeRoot' -- new base is '$base'");
  }
 }
 switchUsers($uid,$gid) if $runAsUser || $runAsGroup;
 # create folders if they're missing
 makeDirs($base,'bak');
 foreach my $c (@Collections) {
  makeDirs($base,${$c}) if ${$c};
 }
 foreach my $c (@Config) {
  my $l=$c->[0];
  if ($c->[1]=~/\*$/ && ${$l}=~/^ *file: *(.+)/i && $1) {
   # the option list is actually saved in a file.
   my ($dir)=$1=~/(.*[\\\/])/;
   makeDirs($base,$dir);
  }
 }
 makeDirs($base,'data/reports');
 makeDirs($base,'data'); # for asspstats.sav
 my @dbs=('spamdb','whitelistdb','redlistdb','dnsbl','greylist','delaydb','ratelimitdb','corpusdb');
 foreach my $d (@dbs) {
  if (${$d}) {
   my ($dir)=${$d}=~/(.*[\\\/])/;
   makeDirs($base,$dir);
  }
 }
 if ($logfile) {
  my ($dir)=$logfile=~/(.*[\\\/])/;
  makeDirs($base,$dir);
 }
 makeDirs($base,'tmp');
 # check directories/files integrity
 mlog(0,"warning: directory does not exist or empty: '$base/images' (web admin interface may be unusable)") if dirEmpty("$base/images");
}

sub initTasks {
 newTask(taskOptionFilesReload(),'NORM',0,'M');
 newTask(taskMaintenance(),'NORM',0,'M');
 newTask(taskUploadStats(),'NORM',0,'M');
 newTask(taskDownloadGrey(),'NORM',0,'M');
 newTask(taskInitAv(),'IDLE',0,'M') if !$AvUseClamAV && $AvDbs;
 newTask(taskReloadAv(),'NORM',0,'M');
 newTask(taskServiceCheck(),'HIGH',0,'M') if $AsAService;
 newTask(taskRestartEvery(),'NORM',0,'M');
 newTask(taskNewSMTPConnection($Lsn),'NORM',0,'S') if $Lsn;
 newTask(taskNewWebConnection($WebSocket),'NORM',0,'W') if $WebSocket;
 newTask(taskNewSMTPConnection($Lsn2),'NORM',0,'S') if $Lsn2;
 newTask(taskNewSMTPConnection($Relay),'NORM',0,'S') if $Relay;
 newTask(taskStats(),'HIGH',0,'M');
}

sub taskInitAv {
 return coro(sub{&jump;
  mlog(0,'loading virus signature database ...');
  return call('L1',Av->init({path=>($AvPath || $base),databases=>$AvDbs})); L1:
  mlog(0,'virus signature database loaded; count='.Av->count);
 });
}

sub taskOptionFilesReload {
 return coro(sub{&jump;
  while (1) {
   waitTaskDelay(0,60);
   return cede('L1'); L1:
   optionFilesReload();
  }
 });
}

sub taskMaintenance {
 return coro(sub{&jump;
  while (1) {
   waitTaskDelay(0,$MaintenanceInterval);
   return cede('L1'); L1:
   return call('L2',saveDatabases()); L2:
   return call('L3',cleanDelayDB()); L3:
   return call('L4',cleanRateLimitDB()); L4:
  }
 });
}

sub taskReloadAv {
 return coro(sub{&jump;
  while (1) {
   unless (!$AvUseClamAV && $AvDbs) {
    waitTaskDelay(0,60);
    return cede('L1'); L1:
    next;
   }
   waitTaskDelay(0,180);
   return cede('L2'); L2:
   if (Av->checkReload()) {
    mlog(0,'reloading virus signature database ...');
    return call('L3',Av->loadAll()); L3:
    mlog(0,'virus signature database reloaded; count='.Av->count);
   }
  }
 });
}

sub taskRestartEvery {
 return coro(sub{&jump;
  while (1) {
   unless ($RestartEvery) {
    waitTaskDelay(0,60);
    return cede('L1'); L1:
    next;
   }
   waitTaskDelay(0,$RestartEvery);
   return cede('L2'); L2:
   next unless $RestartEvery;
   while (scalar keys %Con) {
    waitTaskDelay(0,1);
    return cede('L3'); L3:
   }
   # time to quit -- after endtime and we're bored
   return call('L4',restart()); L4:
  }
 });
}

sub taskStats {
 my ($prbytesClientSMTP,$pwbytesClientSMTP,$drbytesClientSMTP,$dwbytesClientSMTP,$prtimeClientSMTP,$pwtimeClientSMTP,$drtimeClientSMTP,$dwtimeClientSMTP);
 my ($prbytesServerSMTP,$pwbytesServerSMTP,$drbytesServerSMTP,$dwbytesServerSMTP,$prtimeServerSMTP,$pwtimeServerSMTP,$drtimeServerSMTP,$dwtimeServerSMTP);
 my ($prbytesRelaySMTP,$pwbytesRelaySMTP,$drbytesRelaySMTP,$dwbytesRelaySMTP,$prtimeRelaySMTP,$pwtimeRelaySMTP,$drtimeRelaySMTP,$dwtimeRelaySMTP);
 my ($prbytesSMTP,$pwbytesSMTP,$drbytesSMTP,$dwbytesSMTP,$prtimeSMTP,$pwtimeSMTP,$drtimeSMTP,$dwtimeSMTP,$rbytesSMTP,$wbytesSMTP,$rtimeSMTP,$wtimeSMTP);
 my ($kernel_calls,$kernel_time,$idle_time,$user_time,$class,$v,%task_created,%task_finished,%task_calls,%task_time,$cpu_time);
 my ($task_min_time_user,$task_max_time_user,$max_active_total,$max_active,$l);
 return coro(sub{&jump;
  $prbytesClientSMTP=$pwbytesClientSMTP=$drbytesClientSMTP=$dwbytesClientSMTP=$prtimeClientSMTP=$pwtimeClientSMTP=$drtimeClientSMTP=$dwtimeClientSMTP=0;
  $prbytesServerSMTP=$pwbytesServerSMTP=$drbytesServerSMTP=$dwbytesServerSMTP=$prtimeServerSMTP=$pwtimeServerSMTP=$drtimeServerSMTP=$dwtimeServerSMTP=0;
  $prbytesRelaySMTP=$pwbytesRelaySMTP=$drbytesRelaySMTP=$dwbytesRelaySMTP=$prtimeRelaySMTP=$pwtimeRelaySMTP=$drtimeRelaySMTP=$dwtimeRelaySMTP=0;
  $prbytesSMTP=$pwbytesSMTP=$drbytesSMTP=$dwbytesSMTP=$prtimeSMTP=$pwtimeSMTP=$drtimeSMTP=$dwtimeSMTP=$rbytesSMTP=$wbytesSMTP=$rtimeSMTP=$wtimeSMTP=0;
  $kernel_calls=$kernel_time=$idle_time=$user_time=0;
  ($cpuUsage,$cpuUsageKernel,$cpuUsageUser,$cpuUsageM,$cpuUsageS,$cpuUsageW)=($CanStatCPU ? 0 : 'n/a')x6;
  while (1) {
   waitTaskDelay(0,5);
   return cede('L1'); L1:
   # calculate deltas
   $prbytesClientSMTP=$Stats{prbytesClientSMTP}-$prbytesClientSMTP;
   $pwbytesClientSMTP=$Stats{pwbytesClientSMTP}-$pwbytesClientSMTP;
   $drbytesClientSMTP=$Stats{drbytesClientSMTP}-$drbytesClientSMTP;
   $dwbytesClientSMTP=$Stats{dwbytesClientSMTP}-$dwbytesClientSMTP;
   $prtimeClientSMTP=$Stats{prtimeClientSMTP}-$prtimeClientSMTP;
   $pwtimeClientSMTP=$Stats{pwtimeClientSMTP}-$pwtimeClientSMTP;
   $drtimeClientSMTP=$Stats{drtimeClientSMTP}-$drtimeClientSMTP;
   $dwtimeClientSMTP=$Stats{dwtimeClientSMTP}-$dwtimeClientSMTP;
   $prbytesServerSMTP=$Stats{prbytesServerSMTP}-$prbytesServerSMTP;
   $pwbytesServerSMTP=$Stats{pwbytesServerSMTP}-$pwbytesServerSMTP;
   $drbytesServerSMTP=$Stats{drbytesServerSMTP}-$drbytesServerSMTP;
   $dwbytesServerSMTP=$Stats{dwbytesServerSMTP}-$dwbytesServerSMTP;
   $prtimeServerSMTP=$Stats{prtimeServerSMTP}-$prtimeServerSMTP;
   $pwtimeServerSMTP=$Stats{pwtimeServerSMTP}-$pwtimeServerSMTP;
   $drtimeServerSMTP=$Stats{drtimeServerSMTP}-$drtimeServerSMTP;
   $dwtimeServerSMTP=$Stats{dwtimeServerSMTP}-$dwtimeServerSMTP;
   $prbytesRelaySMTP=$Stats{prbytesRelaySMTP}-$prbytesRelaySMTP;
   $pwbytesRelaySMTP=$Stats{pwbytesRelaySMTP}-$pwbytesRelaySMTP;
   $drbytesRelaySMTP=$Stats{drbytesRelaySMTP}-$drbytesRelaySMTP;
   $dwbytesRelaySMTP=$Stats{dwbytesRelaySMTP}-$dwbytesRelaySMTP;
   $prtimeRelaySMTP=$Stats{prtimeRelaySMTP}-$prtimeRelaySMTP;
   $pwtimeRelaySMTP=$Stats{pwtimeRelaySMTP}-$pwtimeRelaySMTP;
   $drtimeRelaySMTP=$Stats{drtimeRelaySMTP}-$drtimeRelaySMTP;
   $dwtimeRelaySMTP=$Stats{dwtimeRelaySMTP}-$dwtimeRelaySMTP;
   ($task_min_time_user,$task_max_time_user)=();
   while (($class,$v)=each(%TaskStats)) {
    $Stats{"taskCreated$class"}+=$task_created{$class}=$v->{created}-$task_created{$class};
    $Stats{"taskFinished$class"}+=$task_finished{$class}=$v->{finished}-$task_finished{$class};
    $Stats{"taskCalls$class"}+=$task_calls{$class}=$v->{calls}-$task_calls{$class};
    $Stats{"taskTime$class"}+=$task_time{$class}=$v->{user_time}-$task_time{$class};
    $Stats{"taskMinTime$class"}=$TaskStats{$class}->{min_user_time};
    $Stats{"taskMaxTime$class"}=$TaskStats{$class}->{max_user_time};
    $task_min_time_user=$TaskStats{$class}->{min_user_time} if $TaskStats{$class}->{min_user_time}<$task_min_time_user || !$task_min_time_user;
    $task_max_time_user=$TaskStats{$class}->{max_user_time} if $TaskStats{$class}->{max_user_time}>$task_max_time_user;
   }
   $Stats{taskCallsKernel}+=$kernel_calls=$KernelStats{calls}-$kernel_calls;
   $Stats{taskTimeKernel}+=$kernel_time=$KernelStats{kernel_time}-$kernel_time;
   $Stats{taskMinTimeKernel}=$KernelStats{min_kernel_time};
   $Stats{taskMaxTimeKernel}=$KernelStats{max_kernel_time};
   $Stats{taskTimeIdle}+=$idle_time=$KernelStats{idle_time}-$idle_time;
   $Stats{taskTimeUser}+=$user_time=$KernelStats{user_time}-$user_time;
   $Stats{taskMinTimeUser}=$task_min_time_user;
   $Stats{taskMaxTimeUser}=$task_max_time_user;
   # calculate stats
   $prtputClientSMTP=$prtimeClientSMTP==0 ? 0 : $prbytesClientSMTP/$prtimeClientSMTP;
   $pwtputClientSMTP=$pwtimeClientSMTP==0 ? 0 : $pwbytesClientSMTP/$pwtimeClientSMTP;
   $drtputClientSMTP=$drtimeClientSMTP==0 ? 0 : $drbytesClientSMTP/$drtimeClientSMTP;
   $dwtputClientSMTP=$dwtimeClientSMTP==0 ? 0 : $dwbytesClientSMTP/$dwtimeClientSMTP;
   $prtputServerSMTP=$prtimeServerSMTP==0 ? 0 : $prbytesServerSMTP/$prtimeServerSMTP;
   $pwtputServerSMTP=$pwtimeServerSMTP==0 ? 0 : $pwbytesServerSMTP/$pwtimeServerSMTP;
   $drtputServerSMTP=$drtimeServerSMTP==0 ? 0 : $drbytesServerSMTP/$drtimeServerSMTP;
   $dwtputServerSMTP=$dwtimeServerSMTP==0 ? 0 : $dwbytesServerSMTP/$dwtimeServerSMTP;
   $prtputRelaySMTP=$prtimeRelaySMTP==0 ? 0 : $prbytesRelaySMTP/$prtimeRelaySMTP;
   $pwtputRelaySMTP=$pwtimeRelaySMTP==0 ? 0 : $pwbytesRelaySMTP/$pwtimeRelaySMTP;
   $drtputRelaySMTP=$drtimeRelaySMTP==0 ? 0 : $drbytesRelaySMTP/$drtimeRelaySMTP;
   $dwtputRelaySMTP=$dwtimeRelaySMTP==0 ? 0 : $dwbytesRelaySMTP/$dwtimeRelaySMTP;
   $prbytesSMTP=$prbytesClientSMTP+$prbytesServerSMTP+$prbytesRelaySMTP;
   $pwbytesSMTP=$pwbytesClientSMTP+$pwbytesServerSMTP+$pwbytesRelaySMTP;
   $drbytesSMTP=$drbytesClientSMTP+$drbytesServerSMTP+$drbytesRelaySMTP;
   $dwbytesSMTP=$dwbytesClientSMTP+$dwbytesServerSMTP+$dwbytesRelaySMTP;
   $prtimeSMTP=$prtimeClientSMTP+$prtimeServerSMTP+$prtimeRelaySMTP;
   $pwtimeSMTP=$pwtimeClientSMTP+$pwtimeServerSMTP+$pwtimeRelaySMTP;
   $drtimeSMTP=$drtimeClientSMTP+$drtimeServerSMTP+$drtimeRelaySMTP;
   $dwtimeSMTP=$dwtimeClientSMTP+$dwtimeServerSMTP+$dwtimeRelaySMTP;
   $rbytesSMTP=$prbytesSMTP+$drbytesSMTP;
   $wbytesSMTP=$pwbytesSMTP+$dwbytesSMTP;
   $rtimeSMTP=$prtimeSMTP+$drtimeSMTP;
   $wtimeSMTP=$pwtimeSMTP+$dwtimeSMTP;
   $prtputSMTP=$prtimeSMTP==0 ? 0 : $prbytesSMTP/$prtimeSMTP;
   $pwtputSMTP=$pwtimeSMTP==0 ? 0 : $pwbytesSMTP/$pwtimeSMTP;
   $drtputSMTP=$drtimeSMTP==0 ? 0 : $drbytesSMTP/$drtimeSMTP;
   $dwtputSMTP=$dwtimeSMTP==0 ? 0 : $dwbytesSMTP/$dwtimeSMTP;
   $rtputSMTP=$rtimeSMTP==0 ? 0 : $rbytesSMTP/$rtimeSMTP;
   $wtputSMTP=$wtimeSMTP==0 ? 0 : $wbytesSMTP/$wtimeSMTP;
   $Stats{prtputMaxClientSMTP}=$prtputClientSMTP if $prtputClientSMTP>$Stats{prtputMaxClientSMTP};
   $Stats{pwtputMaxClientSMTP}=$pwtputClientSMTP if $pwtputClientSMTP>$Stats{pwtputMaxClientSMTP};
   $Stats{drtputMaxClientSMTP}=$drtputClientSMTP if $drtputClientSMTP>$Stats{drtputMaxClientSMTP};
   $Stats{dwtputMaxClientSMTP}=$dwtputClientSMTP if $dwtputClientSMTP>$Stats{dwtputMaxClientSMTP};
   $Stats{prtputMaxServerSMTP}=$prtputServerSMTP if $prtputServerSMTP>$Stats{prtputMaxServerSMTP};
   $Stats{pwtputMaxServerSMTP}=$pwtputServerSMTP if $pwtputServerSMTP>$Stats{pwtputMaxServerSMTP};
   $Stats{drtputMaxServerSMTP}=$drtputServerSMTP if $drtputServerSMTP>$Stats{drtputMaxServerSMTP};
   $Stats{dwtputMaxServerSMTP}=$dwtputServerSMTP if $dwtputServerSMTP>$Stats{dwtputMaxServerSMTP};
   $Stats{prtputMaxRelaySMTP}=$prtputRelaySMTP if $prtputRelaySMTP>$Stats{prtputMaxRelaySMTP};
   $Stats{pwtputMaxRelaySMTP}=$pwtputRelaySMTP if $pwtputRelaySMTP>$Stats{pwtputMaxRelaySMTP};
   $Stats{drtputMaxRelaySMTP}=$drtputRelaySMTP if $drtputRelaySMTP>$Stats{drtputMaxRelaySMTP};
   $Stats{dwtputMaxRelaySMTP}=$dwtputRelaySMTP if $dwtputRelaySMTP>$Stats{dwtputMaxRelaySMTP};
   $Stats{prtputMaxSMTP}=$prtputSMTP if $prtputSMTP>$Stats{prtputMaxSMTP};
   $Stats{pwtputMaxSMTP}=$pwtputSMTP if $pwtputSMTP>$Stats{pwtputMaxSMTP};
   $Stats{drtputMaxSMTP}=$drtputSMTP if $drtputSMTP>$Stats{drtputMaxSMTP};
   $Stats{dwtputMaxSMTP}=$dwtputSMTP if $dwtputSMTP>$Stats{dwtputMaxSMTP};
   $Stats{rtputMaxSMTP}=$rtputSMTP if $rtputSMTP>$Stats{rtputMaxSMTP};
   $Stats{wtputMaxSMTP}=$wtputSMTP if $wtputSMTP>$Stats{wtputMaxSMTP};
   ($max_active_total)=();
   while (($class,$v)=each(%TaskStats)) {
    $max_active=$Stats{"taskCreated$class"}-$Stats{"taskFinished$class"};
    $Stats{"taskMaxActive$class"}=$max_active if $max_active>$Stats{"taskMaxActive$class"};
    $max_active_total+=$max_active;
   }
   $Stats{taskMaxActive}=$max_active_total if $max_active_total>$Stats{taskMaxActive};
   $Stats{taskMaxQueue}=$KernelStats{max_queue} || 0;
   $Stats{taskMaxQueueHigh}=$KernelStats{max_high_queue} || 0;
   $Stats{taskMaxQueueNorm}=$KernelStats{max_norm_queue} || 0;
   $Stats{taskMaxQueueIdle}=$KernelStats{max_idle_queue} || 0;
   $Stats{taskMaxQueueWait}=$KernelStats{max_wait_queue} || 0;
   $Stats{taskMaxQueueSuspend}=$KernelStats{max_suspend_queue} || 0;
   $cpu_time=$kernel_time+$idle_time+$user_time;
   $cpuUsage=$CanStatCPU ? $cpu_time==0 ? 0 : sprintf("%.1f%%",100*($kernel_time+$user_time)/$cpu_time) : 'n/a';
   $cpuUsageKernel=$CanStatCPU ? $cpu_time==0 ? 0 : sprintf("%.1f%%",100*$kernel_time/$cpu_time) : 'n/a';
   $cpuUsageUser=$CanStatCPU ? $cpu_time==0 ? 0 : sprintf("%.1f%%",100*$user_time/$cpu_time) : 'n/a';
   while (($class,$v)=each(%task_time)) {
    ${"cpuUsage$class"}=$CanStatCPU ? $cpu_time==0 ? 0 : sprintf("%.1f%%",100*$v/$cpu_time) : 'n/a';
   }
   # prepare deltas
   $prbytesClientSMTP=$Stats{prbytesClientSMTP};
   $pwbytesClientSMTP=$Stats{pwbytesClientSMTP};
   $drbytesClientSMTP=$Stats{drbytesClientSMTP};
   $dwbytesClientSMTP=$Stats{dwbytesClientSMTP};
   $prbytesServerSMTP=$Stats{prbytesServerSMTP};
   $pwbytesServerSMTP=$Stats{pwbytesServerSMTP};
   $drbytesServerSMTP=$Stats{drbytesServerSMTP};
   $dwbytesServerSMTP=$Stats{dwbytesServerSMTP};
   $prtimeClientSMTP=$Stats{prtimeClientSMTP};
   $pwtimeClientSMTP=$Stats{pwtimeClientSMTP};
   $drtimeClientSMTP=$Stats{drtimeClientSMTP};
   $dwtimeClientSMTP=$Stats{dwtimeClientSMTP};
   $prtimeServerSMTP=$Stats{prtimeServerSMTP};
   $pwtimeServerSMTP=$Stats{pwtimeServerSMTP};
   $drtimeServerSMTP=$Stats{drtimeServerSMTP};
   $dwtimeServerSMTP=$Stats{dwtimeServerSMTP};
   $prbytesRelaySMTP=$Stats{prbytesRelaySMTP};
   $pwbytesRelaySMTP=$Stats{pwbytesRelaySMTP};
   $drbytesRelaySMTP=$Stats{drbytesRelaySMTP};
   $dwbytesRelaySMTP=$Stats{dwbytesRelaySMTP};
   $prtimeRelaySMTP=$Stats{prtimeRelaySMTP};
   $pwtimeRelaySMTP=$Stats{pwtimeRelaySMTP};
   $drtimeRelaySMTP=$Stats{drtimeRelaySMTP};
   $dwtimeRelaySMTP=$Stats{dwtimeRelaySMTP};
   while (($class,$v)=each(%TaskStats)) {
    $task_created{$class}=$v->{created};
    $task_finished{$class}=$v->{finished};
    $task_calls{$class}=$v->{calls};
    $task_time{$class}=$v->{user_time};
   }
   $kernel_calls=$KernelStats{calls};
   $kernel_time=$KernelStats{kernel_time};
   $idle_time=$KernelStats{idle_time};
   $user_time=$KernelStats{user_time};
  }
 });
}

sub MainLoop {
 my $wait=shift; # keep it short enough for servicecheck to be called regularly

return unless $wait;

 $wait||=1;
 my ($cpuIdleTime,$cpuTime)=(0)x2;

## $wait=0 if @Tasks;

 $LoopStart=$CanStatCPU ? (Time::HiRes::time()) : time;
 $LoopMiddle||=$LoopStart;
 $cpuIdleTime-=$LoopStart; $cpuTime-=$LoopMiddle;

 my ($canread,$canwrite)=IO::Select->select($readable,$writable,undef,$wait);

 $LoopMiddle=$CanStatCPU ? (Time::HiRes::time()) : time;
 $cpuIdleTime+=$LoopMiddle; $cpuTime+=$LoopMiddle;

 if ($CanStatCPU) {
  $Stats{cpuTime}+=$cpuTime;
  $Stats{cpuIdleTime}+=$cpuIdleTime;
  # envelope following filter with instant rise and decay time of .5 second
  $cpuUsagePrev=$cpuUsage*exp(-(0.693/0.5)*$cpuTime);
  $cpuUsage=($cpuTime==0 ? 0 : 1-$cpuIdleTime/$cpuTime);
  $cpuUsage=$cpuUsagePrev if $cpuUsage<$cpuUsagePrev;
 }

 handleSelected($canread,$canwrite);

## if (my $ret=shift @Tasks) {
##  push(@Tasks,$ret) if $ret->();
##mlog(0,'here');
## }

 if ($LoopMiddle>=$nextServiceCheck) {
  serviceCheck(); # for win32 services
  $nextServiceCheck=int($LoopMiddle)+5;
 }
 # timer related issues
 if ($wait && abs($cpuIdleTime-$wait)<=0.5) {
  # noactive connections -- check for maintenance
  if ($LoopMiddle>=$nextMaintenance) {
   saveDatabases();
   cleanDelayDB();
   cleanRateLimitDB();
   $nextMaintenance=int($LoopMiddle)+$MaintenanceInterval;
  }
  uploadStats() if $totalizeSpamStats && $LoopMiddle>=$Stats{nextUpload};
  downloadGrey() if !$nogreydownload && $greylist && (!$NextGreylistDownload || $LoopMiddle>=$NextGreylistDownload);
  if (!$AvUseClamAV && $AvDbs && Av->checkReload()) {
   mlog(0,'reloading virus signature database ...');
   Av->loadAll();
   mlog(0,'virus signature database reloaded; count='.Av->count);
  }
 }
 my $opencon=(keys %Con);
 if ($RestartEvery && $LoopMiddle>=$endtime && $opencon==0 || $doShutdown && $LoopMiddle>=$doShutdown) {
  # time to quit -- after endtime and we're bored, or doShutdown time has elapsed.
  saveDatabases();
  mlog(0,'restarting');
  if ($AsAService) {
   exec('cmd.exe /C net stop ASSPSMTP & net start ASSPSMTP');
  } else {
   exit 1;
  }
 }
}

# called during long operations to keep processing priority data
sub PeekLoop {
 return;
}

sub handleSelected {
 my ($canread,$canwrite)=@_;
 foreach my $fh (@$canwrite) {
  vec(my $rout,fileno($fh),1)=1;
  next unless select('',$rout,'',0)>0;
  my $this=$Con{$fh};
  if (length($this->{outgoing})) {
   my $written=syswrite($fh,$this->{outgoing},$OutgoingBufSize);
   $this->{outgoing}=substr($this->{outgoing},$written);
   # test for highwater mark
   if ($this->{paused} && length($this->{outgoing})<$OutgoingBufSize && $written>0) {
##    $readable->add($this->{friend});
    $readable->add($this->{friend}) unless $SocketCalls{$this->{friend}}->{busy};
    $this->{paused}=0;
   }
  }
  $writable->remove($fh) if length($this->{outgoing})==0;
 }
 foreach my $fh (@$canread) {
  vec(my $rin,fileno($fh),1)=1;
  next unless select($rin,'','',0)>0;
  my $call=$SocketCalls{$fh};
  next if $call->{busy};
##  # synchronize calls
####
##  $readable->remove($fh);
##  $call->{busy}=1;
##  $call->{handler}->($fh);
##  $call->{busy}=0;
####
##  $readable->add($fh) unless $Con{$fh}->{paused};

  # synchronize calls
##
  $readable->remove($fh);
  $call->{busy}=1;
  if ($call->{handler}->()) {
  } else {
   $call->{busy}=0;
  }
##
  $readable->add($fh) unless $Con{$fh}->{paused};


 }


 # close timed-out connections
 my @rhs=$readable->handles();
 foreach my $fh (@rhs) {
  next if $SocketCalls{$fh}->{busy};
  my $this=$Con{$fh};
  if ($this->{timeout} && ($this->{last_read}+$this->{timeout})<time) {
   # connection timed out
   my $sfh=$this->{sfh};
   return if checkRateLimit($sfh,'msgAborted',1,0)<0;
   my $err="client read timeout ($SMTPreadtimeout) -- dropping connection";
   mlog($sfh,$err);
   $Con{$sfh}->{stats}='msgAborted';
   sendError($sfh,"($err)",1);
  }
 }
}

#####################################################################################
#                SMTP Socket handlers

sub taskNewSMTPConnection {
 my $fh=shift;
 my ($time,$client,$server,$destination,$this,$ip,$port,$tztime,$tz,$match,$net,$sessCnt);
 return coro(sub{&jump;
  while ($fh->opened()) {
   waitTaskRead(0,$fh,7);
   return cede('L1'); L1:
   next unless getTaskWaitResult(0);
   $time=time;
   ($client,$server,$destination)=();
   # select destination
   if ($fh==$Relay) {
    # a relay connection -- destination is the relayhost
    $destination=$relayHost;
   } elsif ($smtpAuthServer && $fh==$Lsn2) {
    # connection on the Second Listen port
    $destination=$smtpAuthServer;
   } else {
    $destination=$smtpDestination;
   }
   unless ($client=$fh->accept) {
    mlog(0,'accept failed -- aborting connection');
    next;
   }
   binmode($client);
   $server=new IO::Socket::INET(Proto=>'tcp',PeerAddr=>$destination,Timeout=>2);
   unless ($server) {
    $client->close();
    mlog(0,"couldn't create server socket to $destination -- aborting connection");
    next;
   }
   binmode($server);
   addfh($client,\&getLine,$server);
   $this=$Con{$client};
   $this->{isClient}=1;
   $this->{isRelay}=($fh==$Relay);
   $this->{timeout}=$SMTPreadtimeout;
   $ip=$this->{ip};
   $port=$this->{port};
   $this->{mISPRE}=matchIP($ip,'ispip');
   $this->{mNLOGRE}=matchIP($ip,'noLog');
   $this->{mNRLRE}=matchIP($ip,'noRateLimit');
   $this->{mAMRE}=matchIP($ip,'acceptAllMail');
   if (ok2Relay($client) || $this->{isRelay}) {
    $this->{relayok}=1;
   }
   $tztime=$UseLocalTime ? localtime() : gmtime();
   $tz=$UseLocalTime ? tzStr() : '+0000';
   $tztime=~s/... (...) +(\d+) (........) (....)/$2 $1 $4 $3/;
   $this->{rcvd}="Received: from $ip ([$ip] helo=) by $myName; $tztime $tz\015\012";
   if ($sendNoopInfo) {
    addfh($server,\&skipok,$client);
    $Con{$server}->{noop}="NOOP Connection from: $ip, $tztime $tz relayed by $myName\015\012";
   } else {
    addfh($server,\&reply,$client);
   }
   $Con{$server}->{isServer}=1;
   $Con{$server}->{isRelay}=$this->{isRelay};
   if ($this->{isRelay} || $this->{relayok} || $this->{mISPRE} || matchIP($ip,'noGreetDelay')) {
    $Con{$server}->{greetdelay}=-1;
   } else {
    suspendTask($Con{$client}->{itid}); # we want the \&reply sub to be called first (earlytalkers)
    if ($fh==$Lsn2) {
     # connection on the Second Listen port
     $Con{$server}->{greetdelay}=$GreetDelay2;
    } else {
     $Con{$server}->{greetdelay}=$GreetDelay;
    }
   }
   # reset state
   stateReset($client);
   # add SMTP session
   addSession($client);
   # set session fh (sfh)
   $this->{sfh}=$Con{$server}->{sfh}=$client;
   slog($client,"(connected $ip:$port)",0,'I');
   slog($server,"(connected $destination)",1,'I');
   # shutting down ?
   if ($shuttingDown) {
    mlog(0,"connection from $ip:$port rejected -- shutdown/restart process is in progress") if $ConnectionLog && !$this->{mNLOGRE};
    sendError($client,"421 <$myName> Service not available, closing transmission channel");
    next;
   }
   # ip connection filtering
   if ($match=matchIP($ip,'denySMTPConnections')) {
    $match=$match==1 ? '' : " ($match)";
    mlog(0,"connection from $ip:$port$match rejected by denySMTPConnections") if $ConnectionLog && !$this->{mNLOGRE};
    sendError($client,"(connection$match rejected by denySMTPConnections)",1);
    $Stats{smtpConnDenied}++;
    next;
   }
   mlog(0,"connected: $ip:$port") if $ConnectionLog && !$this->{mNLOGRE};
   # per ip smtp sessions limiting
   $net=ipNetwork($ip,24);
   if ($maxSMTPipSessions && $SMTPipSessions{$net}>$maxSMTPipSessions && !$this->{mISPRE} && !$this->{mAMRE}) {
    mlog(0,"limiting $ip connections") if $SessionLimitLog;
    sendError($client,"421 <$myName> Too many concurrent SMTP sessions, please try again later");
    $Stats{smtpConnLimitIP}++;
    next;
   }
   # overall smtp sessions limiting
   $sessCnt=keys %SMTPSessions;
   if ($maxSMTPSessions && $sessCnt>$maxSMTPSessions) {
    mlog(0,'limiting total connections') if $SessionLimitLog;
    sendError($client,"421 <$myName> Too many concurrent SMTP sessions, please try again later");
    $Stats{smtpConnLimit}++;
    next;
   }
   # increment Stats
   $Stats{smtpMaxConcurrentSessions}=$sessCnt if $sessCnt>$Stats{smtpMaxConcurrentSessions};
   if ($this->{mNLOGRE}) {
    $Stats{smtpConnNotLogged}++;
   } else {
    $Stats{smtpConn}++;
   }
  }
 });
}

sub NewSimSMTPConnection {
 my ($fh,$ip,$port)=@_;
 # check if options files have been updated and need to be re-read
 # check for updates each 60 seconds
 my $time=time;
 my $client=$fh; # accept()
 $server=new IO::Socket::INET(Proto=>'tcp',PeerAddr=>$smtpDestination,Timeout=>2);
 unless ($server) {
  mlog(0,"couldn't create server socket to $smtpDestination -- aborting SM connection");
  return;
 }
 addSimfh($client,\&getLine,$server,$ip,$port);
 my $this=$Con{$client};
 $this->{connected}=1;
 $this->{isClient}=1;
 $this->{isRelay}=0;
 $this->{timeout}=0;
 $this->{mISPRE}=matchIP($ip,'ispip');
 $this->{mNLOGRE}=matchIP($ip,'noLog');
 $this->{mNRLRE}=matchIP($ip,'noRateLimit');
 $this->{mAMRE}=matchIP($ip,'acceptAllMail');
 $this->{relayok}=1 if ok2Relay($client);
 my $tztime=$UseLocalTime ? localtime() : gmtime();
 my $tz=$UseLocalTime ? tzStr() : '+0000';
 $tztime=~s/... (...) +(\d+) (........) (....)/$2 $1 $4 $3/;
 $this->{rcvd}="Received: from $ip ([$ip] helo=) by $myName; $tztime $tz\015\012";
 addfh($server,\&SMhelo,$client);
 if ($sendNoopInfo) {
  $Con{$server}->{noop}="NOOP Connection from: $ip, $tztime $tz relayed by $myName\015\012";
 }
 $Con{$server}->{isServer}=1;
 $Con{$server}->{isRelay}=$this->{isRelay};
 $Con{$server}->{greetdelay}=-1;
 # reset state
 stateReset($client);
 # add SMTP session
 addSession($client);
 # set session fh (sfh)
 $this->{sfh}=$Con{$server}->{sfh}=$client;
 slog($client,"(connected $ip:$port)",0,'I');
 slog($server,"(connected $smtpDestination)",1,'I');
 # ip connection filtering
 if (my $match=matchIP($ip,'denySMTPConnections')) {
  $match=$match==1 ? '' : " ($match)";
  mlogCond($client,"connection from $ip:$port$match rejected by denySMTPConnections",$ConnectionLog && !$this->{mNLOGRE});
  sendError($client,"(connection$match rejected by denySMTPConnections)",1);
  return;
 }
 mlogCond($client,"connected: $ip:$port",$ConnectionLog && !$this->{mNLOGRE});
}

# when simulating, the data is stuffed into this sub
# with the $buf parameter, not sysread'ed from the socket
sub taskSMTPInTraffic {
 my ($fh,$buf)=@_;
 my ($this,$sfh,$err,$len,$bn,$lbn,$l,$sb);
 return coro(sub{&jump;
  # note: $Con{$fh} may be deleted in $Con{$fh}->{getline}->() !!!
  $this=$Con{$fh};
  while ($fh->opened()) {
   waitTaskRead(0,$fh,7);
   return cede('L1'); L1:
   $sfh=$this->{sfh};
   unless (getTaskWaitResult(0)) {
    next unless $this->{timeout};
##    last unless $fh->opened();
    waitTaskRead(0,$fh,$this->{timeout}-7);
    return cede('L2'); L2:
    unless (getTaskWaitResult(0)) {
     # connection timed out
     return if checkRateLimit($sfh,'msgAborted',1,0)<0;
     $err="client read timeout ($SMTPreadtimeout) -- dropping connection";
     mlogCond($sfh,$err,1);
     $Con{$sfh}->{stats}='msgAborted';
     sendError($sfh,"($err)",1);
     last;
    }
   }
   unless ($fh->sysread($buf,$IncomingBufSize)>0) { # connection closed by peer
    if ($Con{$sfh}->{indata}) {
     return if checkRateLimit($sfh,'msgAborted',1,0)<0;
     $err='connection closed unexpectedly by peer';
     mlogCond($sfh,$err,1);
     slog($fh,'('.needEs($this->{maillength},' byte','s')." received; $err)",0,'I');
     doneStats($sfh,0,'msgAborted');
    } else {
     doneStats($sfh,1);
    }
    doneSession($fh,0);
    last;
   }
   $this->{_}.=$buf;
   if (($sb=$this->{skipbytes})>0) {
    # support for XEXCH50 thankyou Microsoft for making my life miserable
    $len=length($this->{_});
    if ($len>=$sb) {
     addTrafStats($fh,$sb,0);
     # send the binary chunk on to the server
     sendque($this->{friend},substr($this->{_},0,$sb,'')); # four-argument substr()
     delete $this->{skipbytes};
    } else {
     addTrafStats($fh,$len,0);
     # send the binary chunk on to the server
     sendque($this->{friend},$this->{_});
     $this->{skipbytes}=$sb-=$len;
     $this->{_}='';
    }
   }
   while (($bn=index($this->{_},"\015\012"))>=0) {
    $bn+=2; # crlf length
    $l=substr($this->{_},0,$bn,''); # four-argument substr()
    $len=length($l);
    addTrafStats($fh,$len,0);
    $this->{bdata}-=$len if defined($this->{bdata});
    return call('L3',$this->{getline}->($fh,$l)); L3:
    # it's possible that the connection can be deleted 
    # while there's still something in the buffer
    last unless $Con{$fh}; # '$this' may be not valid -- check $Con{$fh}
   }
   # '$this' may be not valid -- check $Con{$fh} instead
   if ($Con{$fh}) {
    $len=length($this->{_});
    if ($len>$MaxBytes) {
     addTrafStats($fh,$len,0);
     $this->{bdata}-=$len if defined($this->{bdata});
     return call('L4',$this->{getline}->($fh,$this->{_})); L4:
     $this->{_}='' if $Con{$fh}; # '$this' may be not valid -- check $Con{$fh} instead
    }
   }
  }
 });
}

sub taskSMTPOutTraffic {
 my $fh=shift;
 my ($this,$written);
 return coro(sub{&jump;
  $this=$Con{$fh};
  while ($fh->opened()) {
   waitTaskWrite(0,$fh,7);
   return cede('L1'); L1:
   next unless getTaskWaitResult(0);
   if (length($this->{outgoing})) {
    $written=syswrite($fh,$this->{outgoing},$OutgoingBufSize);
    substr($this->{outgoing},0,$written,''); # four-argument substr()
    # test for highwater mark
    if ($this->{paused} && length($this->{outgoing})<$OutgoingBufSize && $written>0) {
     resumeTask($Con{$this->{friend}}->{itid});
     $this->{paused}=0;
    }
   }
   suspendTask(0) unless length($this->{outgoing});
  }
 });
}

sub addTrafStats {
 my ($fh,$rbytes,$wbytes)=@_;
 my $this=$Con{$fh};
 my $sfh=$this->{sfh};
 my $sess=$SMTPSessions{$sfh};
 my $dt=($AvailHiRes ? Time::HiRes::time() : time)-$sess->{marktime};
 my ($rtime,$wtime)=(0)x2;
 $rtime=$dt if $rbytes;
 $wtime=$dt if $wbytes;
 if ($this->{isClient}) {
  if ($this->{isRelay}) {
   # relay side
   if ($Con{$sfh}->{indata}) {
    # SMTP data
    $Con{$sfh}->{drbytesClientSMTP}+=$rbytes;
    $Con{$sfh}->{dwbytesClientSMTP}+=$wbytes;
    $Con{$sfh}->{drtimeClientSMTP}+=$rtime;
    $Con{$sfh}->{dwtimeClientSMTP}+=$wtime;
    $Stats{drbytesRelaySMTP}+=$rbytes;
    $Stats{dwbytesRelaySMTP}+=$wbytes;
    $Stats{drtimeRelaySMTP}+=$rtime;
    $Stats{dwtimeRelaySMTP}+=$wtime;
   } else {
    # SMTP protocol
    $Con{$sfh}->{prbytesClientSMTP}+=$rbytes;
    $Con{$sfh}->{pwbytesClientSMTP}+=$wbytes;
    $Con{$sfh}->{prtimeClientSMTP}+=$rtime;
    $Con{$sfh}->{pwtimeClientSMTP}+=$wtime;
    if ($rtime) {
     $sess->{lbannerClientSMTP}=$rtime if $sess->{lbannerClientSMTP} eq 0;
     $sess->{lminClientSMTP}=$rtime if $rtime<$sess->{lminClientSMTP} || !$sess->{lminClientSMTP};
     $sess->{lmaxClientSMTP}=$rtime if $rtime>$sess->{lmaxClientSMTP};
    }
    $Stats{prbytesRelaySMTP}+=$rbytes;
    $Stats{pwbytesRelaySMTP}+=$wbytes;
    $Stats{prtimeRelaySMTP}+=$rtime;
    $Stats{pwtimeRelaySMTP}+=$wtime;
   }
  } else {
   # client side
   if ($Con{$sfh}->{indata}) {
    # SMTP data
    $Con{$sfh}->{drbytesClientSMTP}+=$rbytes;
    $Con{$sfh}->{dwbytesClientSMTP}+=$wbytes;
    $Con{$sfh}->{drtimeClientSMTP}+=$rtime;
    $Con{$sfh}->{dwtimeClientSMTP}+=$wtime;
    $Stats{drbytesClientSMTP}+=$rbytes;
    $Stats{dwbytesClientSMTP}+=$wbytes;
    $Stats{drtimeClientSMTP}+=$rtime;
    $Stats{dwtimeClientSMTP}+=$wtime;
   } else {
    # SMTP protocol
    $Con{$sfh}->{prbytesClientSMTP}+=$rbytes;
    $Con{$sfh}->{pwbytesClientSMTP}+=$wbytes;
    $Con{$sfh}->{prtimeClientSMTP}+=$rtime;
    $Con{$sfh}->{pwtimeClientSMTP}+=$wtime;
    if ($rtime) {
     $sess->{lbannerClientSMTP}=$rtime if $sess->{lbannerClientSMTP} eq 0;
     $sess->{lminClientSMTP}=$rtime if $rtime<$sess->{lminClientSMTP} || !$sess->{lminClientSMTP};
     $sess->{lmaxClientSMTP}=$rtime if $rtime>$sess->{lmaxClientSMTP};
    }
    $Stats{prbytesClientSMTP}+=$rbytes;
    $Stats{pwbytesClientSMTP}+=$wbytes;
    $Stats{prtimeClientSMTP}+=$rtime;
    $Stats{pwtimeClientSMTP}+=$wtime;
   }
  }
 } elsif ($this->{isServer}) {
  if ($this->{isRelay}) {
   # relay side
   if ($Con{$sfh}->{indata}) {
    # SMTP data
    $Con{$sfh}->{drbytesServerSMTP}+=$rbytes;
    $Con{$sfh}->{dwbytesServerSMTP}+=$wbytes;
    $Con{$sfh}->{drtimeServerSMTP}+=$rtime;
    $Con{$sfh}->{dwtimeServerSMTP}+=$wtime;
    $Stats{drbytesRelaySMTP}+=$rbytes;
    $Stats{dwbytesRelaySMTP}+=$wbytes;
    $Stats{drtimeRelaySMTP}+=$rtime;
    $Stats{dwtimeRelaySMTP}+=$wtime;
   } else {
    # SMTP protocol
    $Con{$sfh}->{prbytesServerSMTP}+=$rbytes;
    $Con{$sfh}->{pwbytesServerSMTP}+=$wbytes;
    $Con{$sfh}->{prtimeServerSMTP}+=$rtime;
    $Con{$sfh}->{pwtimeServerSMTP}+=$wtime;
    if ($wtime) {
     $sess->{lminServerSMTP}=$wtime if $wtime<$sess->{lminServerSMTP} || !$sess->{lminServerSMTP};
     $sess->{lmaxServerSMTP}=$wtime if $wtime>$sess->{lmaxServerSMTP};
    }
    $Stats{prbytesRelaySMTP}+=$rbytes;
    $Stats{pwbytesRelaySMTP}+=$wbytes;
    $Stats{prtimeRelaySMTP}+=$rtime;
    $Stats{pwtimeRelaySMTP}+=$wtime;
   }
  } else {
   # server side
   if ($Con{$sfh}->{indata}) {
    # SMTP data
    $Con{$sfh}->{drbytesServerSMTP}+=$rbytes;
    $Con{$sfh}->{dwbytesServerSMTP}+=$wbytes;
    $Con{$sfh}->{drtimeServerSMTP}+=$rtime;
    $Con{$sfh}->{dwtimeServerSMTP}+=$wtime;
    $Stats{drbytesServerSMTP}+=$rbytes;
    $Stats{dwbytesServerSMTP}+=$wbytes;
    $Stats{drtimeServerSMTP}+=$rtime;
    $Stats{dwtimeServerSMTP}+=$wtime;
   } else {
    # SMTP protocol
    $Con{$sfh}->{prbytesServerSMTP}+=$rbytes;
    $Con{$sfh}->{pwbytesServerSMTP}+=$wbytes;
    $Con{$sfh}->{prtimeServerSMTP}+=$rtime;
    $Con{$sfh}->{pwtimeServerSMTP}+=$wtime;
    if ($wtime) {
     $sess->{lminServerSMTP}=$wtime if $wtime<$sess->{lminServerSMTP} || !$sess->{lminServerSMTP};
     $sess->{lmaxServerSMTP}=$wtime if $wtime>$sess->{lmaxServerSMTP};
    }
    $Stats{prbytesServerSMTP}+=$rbytes;
    $Stats{pwbytesServerSMTP}+=$wbytes;
    $Stats{prtimeServerSMTP}+=$rtime;
    $Stats{pwtimeServerSMTP}+=$wtime;
   }
  }
 }
 $sess->{marktime}+=$dt;
}

sub doneStats {
 my ($fh,$success,$stats)=@_;
 my $this=$Con{$fh};
 my $sfh=$this->{sfh};
 my $sess=$SMTPSessions{$sfh};
 $this->{stats}=$stats if $stats;
 $stats=$this->{stats};
 $Stats{$stats}++ if $stats;
 unless ($this->{isRelay}) {
  if ($success) {
   if ($this->{isClient}) {
    # regular connection
    $stats||='other';
    $Stats{'prbytes'.$stats}+=$Con{$sfh}->{prbytesClientSMTP};
    $Stats{'prtime'.$stats}+=$Con{$sfh}->{prtimeClientSMTP};
    $Stats{'drbytes'.$stats}+=$Con{$sfh}->{drbytesClientSMTP};
    $Stats{'drtime'.$stats}+=$Con{$sfh}->{drtimeClientSMTP};
    $Stats{prbytesClientAccepted}+=$Con{$sfh}->{prbytesClientSMTP};
    $Stats{drbytesClientAccepted}+=$Con{$sfh}->{drbytesClientSMTP};
    $Stats{pwbytesproxied}+=$Con{$sfh}->{pwbytesServerSMTP};
    $Stats{dwbytesproxied}+=$Con{$sfh}->{dwbytesServerSMTP};
   } elsif ($this->{isServer}) {
    # forward spam or return mail connection
    $Stats{'pwbytes'.$stats}+=$this->{pwbytesServerSMTP};
    $Stats{'dwbytes'.$stats}+=$this->{dwbytesServerSMTP};
   }
   $Stats{pwbytesServerPassed}+=$Con{$sfh}->{pwbytesServerSMTP};
   $Stats{dwbytesServerPassed}+=$Con{$sfh}->{dwbytesServerSMTP};
  } else {
   if ($this->{isClient}) {
    # regular connection
    $stats||='otherblocked';
    $Stats{'prbytes'.$stats}+=$Con{$sfh}->{prbytesClientSMTP};
    $Stats{'prtime'.$stats}+=$Con{$sfh}->{prtimeClientSMTP};
    $Stats{'drbytes'.$stats}+=$Con{$sfh}->{drbytesClientSMTP};
    $Stats{'drtime'.$stats}+=$Con{$sfh}->{drtimeClientSMTP};
    $Stats{prbytesClientBlocked}+=$Con{$sfh}->{prbytesClientSMTP};
    $Stats{drbytesClientBlocked}+=$Con{$sfh}->{drbytesClientSMTP};
   } elsif ($this->{isServer}) {
    # forward spam or return mail connection
   }
   $Stats{pwbytesServerAborted}+=$Con{$sfh}->{pwbytesServerSMTP};
   $Stats{dwbytesServerAborted}+=$Con{$sfh}->{dwbytesServerSMTP};
  }
  $Stats{'lbanner'.$stats}+=$sess->{lbannerClientSMTP};
  $Stats{'lmin'.$stats}+=$sess->{lminClientSMTP};
  $Stats{'lmax'.$stats}+=$sess->{lmaxClientSMTP};
 }
 # add counters to session
 $sess->{drbytesClientSMTP}+=$Con{$sfh}->{drbytesClientSMTP};
 $sess->{dwbytesClientSMTP}+=$Con{$sfh}->{dwbytesClientSMTP};
 $sess->{drtimeClientSMTP}+=$Con{$sfh}->{drtimeClientSMTP};
 $sess->{dwtimeClientSMTP}+=$Con{$sfh}->{dwtimeClientSMTP};
 $sess->{prbytesClientSMTP}+=$Con{$sfh}->{prbytesClientSMTP};
 $sess->{pwbytesClientSMTP}+=$Con{$sfh}->{pwbytesClientSMTP};
 $sess->{prtimeClientSMTP}+=$Con{$sfh}->{prtimeClientSMTP};
 $sess->{pwtimeClientSMTP}+=$Con{$sfh}->{pwtimeClientSMTP};
 $sess->{drbytesServerSMTP}+=$Con{$sfh}->{drbytesServerSMTP};
 $sess->{dwbytesServerSMTP}+=$Con{$sfh}->{dwbytesServerSMTP};
 $sess->{drtimeServerSMTP}+=$Con{$sfh}->{drtimeServerSMTP};
 $sess->{dwtimeServerSMTP}+=$Con{$sfh}->{dwtimeServerSMTP};
 $sess->{prbytesServerSMTP}+=$Con{$sfh}->{prbytesServerSMTP};
 $sess->{pwbytesServerSMTP}+=$Con{$sfh}->{pwbytesServerSMTP};
 $sess->{prtimeServerSMTP}+=$Con{$sfh}->{prtimeServerSMTP};
 $sess->{pwtimeServerSMTP}+=$Con{$sfh}->{pwtimeServerSMTP};
 # reset counters
 $Con{$sfh}->{drbytesClientSMTP}=0;
 $Con{$sfh}->{dwbytesClientSMTP}=0;
 $Con{$sfh}->{drtimeClientSMTP}=0;
 $Con{$sfh}->{dwtimeClientSMTP}=0;
 $Con{$sfh}->{prbytesClientSMTP}=0;
 $Con{$sfh}->{pwbytesClientSMTP}=0;
 $Con{$sfh}->{prtimeClientSMTP}=0;
 $Con{$sfh}->{pwtimeClientSMTP}=0;
 $Con{$sfh}->{drbytesServerSMTP}=0;
 $Con{$sfh}->{dwbytesServerSMTP}=0;
 $Con{$sfh}->{drtimeServerSMTP}=0;
 $Con{$sfh}->{dwtimeServerSMTP}=0;
 $Con{$sfh}->{prbytesServerSMTP}=0;
 $Con{$sfh}->{pwbytesServerSMTP}=0;
 $Con{$sfh}->{prtimeServerSMTP}=0;
 $Con{$sfh}->{pwtimeServerSMTP}=0;
}
 
sub addSession {
 my $sfh=shift;
 my $this=$Con{$sfh};
 my $ip=$this->{ip};
 my $port=$this->{port};
 my $sess=$SMTPSessions{$sfh}={};
 $sess->{id}=$SMTPSessionID++;
 $sess->{client}=$ip.':'.$port;
 $sess->{stime}=$AvailHiRes ? Time::HiRes::time() : time; # start time
 $sess->{marktime}=$sess->{stime}; # mark time
 $sess->{msgcnt}=0; # messages count
 $sess->{drbytesClientSMTP}=0;
 $sess->{dwbytesClientSMTP}=0;
 $sess->{drtimeClientSMTP}=0;
 $sess->{dwtimeClientSMTP}=0;
 $sess->{prbytesClientSMTP}=0;
 $sess->{pwbytesClientSMTP}=0;
 $sess->{prtimeClientSMTP}=0;
 $sess->{pwtimeClientSMTP}=0;
 $sess->{drbytesServerSMTP}=0;
 $sess->{dwbytesServerSMTP}=0;
 $sess->{drtimeServerSMTP}=0;
 $sess->{dwtimeServerSMTP}=0;
 $sess->{prbytesServerSMTP}=0;
 $sess->{pwbytesServerSMTP}=0;
 $sess->{prtimeServerSMTP}=0;
 $sess->{pwtimeServerSMTP}=0;
 $sess->{lbannerClientSMTP}=0;  # client banner latency
 $sess->{lminClientSMTP}=0;     # client latency min
 $sess->{lmaxClientSMTP}=0;     # client latency max
 $sess->{lminServerSMTP}=0;     # server latency min
 $sess->{lmaxServerSMTP}=0;     # server latency max
 $SMTPipSessions{ipNetwork($ip,24)}++;
}

# done with a file handle -- close him and his friend(s)
sub doneSession {
 my ($fh,$by)=@_;
 my $this=$Con{$fh};
 my $sfh=$this->{sfh};
 my $sess=$SMTPSessions{$sfh};
 # close connections
 doneConnection($fh,$by);
 doneConnection($this->{friend},1);
 doneTmpBody($fh,3); # close & unlink tmp message body file
 doneClamAV($fh,3); # close COMMAND & STREAM
 # session stats
 my $dur=($AvailHiRes ? Time::HiRes::time() : time)-$sess->{stime} || 1;
 $dur=sprintf("%.1f",$dur) if $dur>1;
 my $msg;
 $msg.=needEs($sess->{msgcnt},' message','s').' of ' if $sess->{msgcnt}>0;
 $msg.=formatDataSize($sess->{prbytesClientSMTP}+$sess->{drbytesClientSMTP},1);
 $msg.=' ('.formatDataSize($sess->{prbytesClientSMTP},1).' / '.formatDataSize($sess->{drbytesClientSMTP},1).')' if $DetailedStats;
 $msg.=' received in '.formatTimeInterval($dur,1);
 if ($AvailHiRes) {
  if ($sess->{prtimeClientSMTP}+$sess->{drtimeClientSMTP}>0) {
   $msg.=' at '.formatDataSize(($sess->{prtimeClientSMTP}+$sess->{drtimeClientSMTP})==0 ? 0 : ($sess->{prbytesClientSMTP}+$sess->{drbytesClientSMTP})/($sess->{prtimeClientSMTP}+$sess->{drtimeClientSMTP}),1).'ps';
   $msg.=' ('.formatDataSize($sess->{prtimeClientSMTP}==0 ? 0 : $sess->{prbytesClientSMTP}/$sess->{prtimeClientSMTP},1).'ps / '.
              formatDataSize($sess->{drtimeClientSMTP}==0 ? 0 : $sess->{drbytesClientSMTP}/$sess->{drtimeClientSMTP},1).'ps)' if $DetailedStats;
  }
  if ($sess->{lminClientSMTP}>0 && $sess->{lmaxClientSMTP}>0) {
   $msg.=' with '.formatTimeInterval($sess->{lbannerClientSMTP},1).' ttfb / '.
                  formatTimeInterval(($sess->{lminClientSMTP}+$sess->{lmaxClientSMTP})/2,1).' avg';
   $msg.=' ('.formatTimeInterval($sess->{lminClientSMTP},1).' - '.
              formatTimeInterval($sess->{lmaxClientSMTP},1).')' if $DetailedStats;
   $msg.=' latency';
  }
 }
 slog($sfh,"($msg)",0,'I');
 if ($AvailHiRes && $ServerSessionLog) {
  $msg=formatDataSize($sess->{pwbytesServerSMTP}+$sess->{dwbytesServerSMTP},1);
  $msg.=' ('.formatDataSize($sess->{pwbytesServerSMTP},1).' / '.formatDataSize($sess->{dwbytesServerSMTP},1).')' if $DetailedStats;
  $msg.=' transmitted';
  if ($sess->{pwtimeServerSMTP}+$sess->{dwtimeServerSMTP}>0) {
   $msg.=' at '.formatDataSize(($sess->{pwtimeServerSMTP}+$sess->{dwtimeServerSMTP})==0 ? 0 : ($sess->{pwbytesServerSMTP}+$sess->{dwbytesServerSMTP})/($sess->{pwtimeServerSMTP}+$sess->{dwtimeServerSMTP}),1).'ps';
   $msg.=' ('.formatDataSize($sess->{pwtimeServerSMTP}==0 ? 0 : $sess->{pwbytesServerSMTP}/$sess->{pwtimeServerSMTP},1).'ps / '.
              formatDataSize($sess->{dwtimeServerSMTP}==0 ? 0 : $sess->{dwbytesServerSMTP}/$sess->{dwtimeServerSMTP},1).'ps)' if $DetailedStats;
  }
  if ($sess->{lminServerSMTP}>0 && $sess->{lmaxServerSMTP}>0) {
   $msg.=' with '.formatTimeInterval(($sess->{lminServerSMTP}+$sess->{lmaxServerSMTP})/2,1).' avg';
   $msg.=' ('.formatTimeInterval($sess->{lminServerSMTP},1).' - '.
              formatTimeInterval($sess->{lmaxServerSMTP},1).')' if $DetailedStats;
  $msg.=' latency';
  }
  slog($sfh,"($msg)",1,'I');
 }
 # update ip sessions count
 my $net=ipNetwork($Con{$sfh}->{ip},24);
 delete $SMTPipSessions{$net} unless --$SMTPipSessions{$net};
 unless ($Con{$sfh}->{simulating}) {
  # dump session to slogfile
  dumpSlog($sfh);
  # remove SMTP session
  delete $SMTPSessions{$sfh};
  # delete the Connection data
  delete $Con{$this->{friend}};
  delete $Con{$fh};
 }
}

# close a file handle & clean up associated records
sub doneConnection {
 my ($fh,$by)=@_;
 return unless $fh; # may have been closed
 my $this=$Con{$fh};
 my $addr=($this->{ip}).':'.($this->{port});
 if ($this->{simulating}) {
##  delete $SocketCalls{$fh};
  return unless $this->{connected};
  if ($by) {
   slog($fh,"(closing connection to $addr)",1,'I');
  } else {
   slog($fh,"(connection to $addr closed by peer)",0,'I');
  }
  # close it
  $this->{connected}=0;
 } else {
  doneTask($this->{itid});
  doneTask($this->{otid});
  return unless $fh->connected();
  if ($by) {
   slog($fh,"(closing connection to $addr)",1,'I');
  } else {
   slog($fh,"(connection to $addr closed by peer)",0,'I');
  }
  # close it
  $fh->close;
 }
}

# adding a socket to the Select structure and Con hash
sub addfh {
 my ($fh,$getline,$friend)=@_;
 $Con{$fh}={};
 my $this=$Con{$fh};
 $this->{ip}=$fh->peerhost();
 $this->{port}=$fh->peerport();
 $this->{getline}=$getline;
 $this->{friend}=$friend;
 binmode($fh);
 $this->{itid}=newTask(taskSMTPInTraffic($fh),'NORM',0,'S');
 $this->{otid}=newTask(taskSMTPOutTraffic($fh),'NORM',0,'S');
}

sub addSimfh {
 my ($fh,$getline,$friend,$ip,$port)=@_;
 $Con{$fh}={};
 my $this=$Con{$fh};
 $this->{simulating}=1;
 $this->{ip}=$ip;
 $this->{port}=$port;
 $this->{getline}=$getline;
 $this->{friend}=$friend;
## $SocketCalls{$fh}->{handler}=''; # empty
}

# sendque enques a string for a socket
sub sendque {
 my ($fh,$message,$slog)=@_;
 return unless $fh; # may have been closed
 my $this=$Con{$fh};
 if ($this->{simulating}) {
  if ($this->{connected}) {
   $this->{outgoing}.=$message;
   addTrafStats($fh,0,length($message));
   slog($fh,$message,1) if $slog;
  }
 } else {
  if ($fh->connected()) {
   $this->{outgoing}.=$message;
   addTrafStats($fh,0,length($message));
   resumeTask($this->{otid});
   if (!$this->{paused} && length($this->{outgoing})>$OutgoingBufSize) {
    suspendTask($Con{$this->{friend}}->{itid});
    $this->{paused}=1;
   }
   slog($fh,$message,1) if $slog;
  } elsif ($this->{paused}) {
   # unpause friend if $fh disconnected
   resumeTask($Con{$this->{friend}}->{itid});
   $this->{paused}=0;
  }
 }
}

#####################################################################################
#                SMTP stuff

# reset everything
sub stateReset {
 my $fh=shift;
 my $this=$Con{$fh};
 $this->{getline}=\&getLine;
 $this->{mailfrom}=$this->{rcpt}=$this->{header}=$this->{myheader}=$this->{body}='';
 $this->{stats}=$this->{tag}=$this->{error}=$this->{mlogbuf}=$this->{checkedattach}='';
 $this->{isbounce}=$this->{invalidSRSBounce}=0;
 $this->{delayed}=$this->{spamfound}=0;
 $this->{inmailfrom}=$this->{indata}=$this->{inerror}=0;
 $this->{coll}=$this->{maillength}=$this->{spamprob}=0;
 $this->{mailfromlocal}=$this->{mailfromonwl}=0;
 $this->{noprocessing}=2; # clear this later if !noprocessing
 # clear these later if !spamLover
 $this->{allLoveSpam}=$this->{allLoveHlSpam}=$this->{allLoveMfSpam}=$this->{allLoveBlSpam}=1;
 $this->{allLoveNoDelaying}=$this->{allLoveSPFSpam}=$this->{allLoveRBLSpam}=$this->{allLoveSRSSpam}=1;
 $this->{allLoveMalformedSpam}=$this->{allLoveBombsSpam}=$this->{allLoveURIBLSpam}=$this->{allLoveBaysSpam}=1;
 $this->{allLoveRateLimitSpam}=1;
 $this->{reporttype}=-1;
 # per connection test-result caches, reuse them
 #  delete $this->{RWLcache};
 #  delete $this->{RBLcache};
 #  delete $this->{Helocache};
 # per message test-result caches, dont reuse
 delete $this->{Sendercache};
 delete $this->{SPFcache};
}

# a line of input has been received from the smtp client
sub getLine {
 my ($fh,$l);
 my ($this,$server,$tf,$srs,$e,$u,$h,$RO_e,$ec,$tt,$tt2,$rcptlocal,$rcptlocaladdress,$err,$reply);
 my ($doRateLimit,$doHelo,$doSender,$doSPF,$doRBL);
 my $sref=$Tasks{$CurTaskID}->{getLine}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  $this=$Con{$fh};
  $server=$this->{friend};
  $this->{inenvelope}=1;
  slog($fh,$l,0);
  unless ($l=~/^[\040-\176]*\015\012/) {
   delayWhiteExpire($fh);
   mlogCond($fh,"invalid character",1);
   sendque($fh,"553 Invalid character\015\012",1);
   checkMaxErrors($fh,'',1,0)<0;
   return;
  }
  if ($l=~/^ *(?:helo|ehlo) .*?([^<>,;"'\(\)\s]+)/i) {
   $this->{helo}=$1;
   $this->{rcvd}=~s/=\)/=$this->{helo}\)/;
   headerWrap($this->{rcvd}); # wrap long lines
   # early (pre-mailfrom) checks, optimize checkRWL() position
   $doHelo=$ValidateHelo && $HeloPosition==1;
   return if $doHelo && ($HeloExtra & 4) && checkHelo($fh)<0;
   if ($doHelo && !($HeloExtra & 4)) {
    return call('L1',checkRWL($fh)); L1:
    unless ($this->{rwlok}) {
     return if $doHelo && !($HeloExtra & 4) && checkHelo($fh)<0;
    }
   }
   return if checkNonLate($fh,0)<0;
   # for testing
   if ($this->{isRelay}) { $l=~s/\Q$this->{helo}\E/$myName/; } else { $l=~s/\Q$this->{helo}\E/$myName\.[$this->{ip}]/; }
  } elsif ($l=~/mail from:\s*<?($EmailAdrRe\@$EmailDomainRe|\s*)>?/io) {
   $this->{mailfrom}=$1;
   $this->{inmailfrom}=1;
   $this->{mailfromlocal}=localMailDomain($this->{mailfrom});
   $this->{mailfromonwl}=$Whitelist{lc $this->{mailfrom}};
   $this->{noprocessing}|=1 if matchSL($this->{mailfrom},'noProcessing');
   $this->{mNMVRE}=matchSLIP($this->{mailfrom},$this->{ip},'noMsgVerify');
   $this->{mNBSRE}=matchSL($this->{mailfrom},'noBombScript');
   $this->{mWLDRE}=$this->{mailfrom}=~$WLDRE;
   $this->{isbounce}=$this->{mailfrom}=~$BSRE;
   # update some Sender Stats
   if ($SenderPosition==1 && ($SenderExtra & 4)) {
    if (!($SenderExtra & 1) && ($this->{noprocessing} & 1)) {
     mlogCond($fh,"sender noprocessing: $this->{mailfrom}",$SenderValLog);
     return if checkRateLimit($fh,'senderUnprocessed',0,0)<0;
     $Stats{senderUnprocessed}++;
    } elsif (!($SenderExtra & 2) && ($this->{mailfromonwl} || $this->{mWLDRE})) {
     mlogCond($fh,"sender whitelisted: $this->{mailfrom}",$SenderValLog);
     return if checkRateLimit($fh,'senderWhitelisted',0,0)<0;
     $Stats{senderWhitelisted}++;
    }
   }
   # early (pre-rcpt) checks, optimize checkRWL() position
   $doRateLimit=$EnableRateLimit && $RateLimitPosition==3 && (($RateLimitExtra & 1) || !($this->{noprocessing} & 1)) && (($RateLimitExtra & 2) || !($this->{mailfromonwl} || $this->{mWLDRE}));
   $doHelo=$ValidateHelo && $HeloPosition==2 && (($HeloExtra & 1) || !($this->{noprocessing} & 1)) && (($HeloExtra & 2) || !($this->{mailfromonwl} || $this->{mWLDRE}));
   $doSender=$ValidateSender && $SenderPosition==1 && (($SenderExtra & 1) || !($this->{noprocessing} & 1)) && (($SenderExtra & 2) || !($this->{mailfromonwl} || $this->{mWLDRE}));
   $doSPF=$CanUseSPF && $ValidateSPF && $SPFPosition==1 && (($SPFExtra & 1) || !($this->{noprocessing} & 1)) && (($SPFExtra & 2) || !($this->{mailfromonwl} || $this->{mWLDRE}));
   $doRBL=$CanUseRBL && $ValidateRBL && $RBLPosition==3 && (($RBLExtra & 1) || !($this->{noprocessing} & 1)) && (($RBLExtra & 2) || !($this->{mailfromonwl} || $this->{mWLDRE}));
   return if $doRateLimit && ($RateLimitExtra & 4) && checkRateLimitBlock($fh,0)<0;
   return if $doHelo && ($HeloExtra & 4) && checkHelo($fh)<0;
   return if $doSender && ($SenderExtra & 4) && checkSender($fh)<0;
   checkSPF($fh) if $doSPF && ($SPFExtra & 4);
   return call('L2',checkRBL($fh)) if $doRBL && ($RBLExtra & 4); L2:
   if ($doRateLimit && !($RateLimitExtra & 4) ||
       $doHelo && !($HeloExtra & 4) ||
       $doSender && !($SenderExtra & 4) ||
       $doSPF && !($SPFExtra & 4) ||
       $doRBL && !($RBLExtra & 4)) {
    return call('L3',checkRWL($fh)); L3:
    # update some Sender Stats
    if ($SenderPosition==1 && !($SenderExtra & 4)) {
     if (!($SenderExtra & 1) && ($this->{noprocessing} & 1)) {
      mlogCond($fh,"sender noprocessing: $this->{mailfrom}",$SenderValLog);
      return if checkRateLimit($fh,'senderUnprocessed',0,0)<0;
      $Stats{senderUnprocessed}++;
     } elsif (!($SenderExtra & 2) && ($this->{mailfromonwl} || $this->{mWLDRE}) || $this->{rwlok}) {
      mlogCond($fh,"sender whitelisted: $this->{mailfrom}",$SenderValLog);
      return if checkRateLimit($fh,'senderWhitelisted',0,0)<0;
      $Stats{senderWhitelisted}++;
     }
    }
    unless ($this->{rwlok}) {
     return if $doRateLimit && !($RateLimitExtra & 4) && checkRateLimitBlock($fh,0)<0;
     return if $doHelo && !($HeloExtra & 4) && checkHelo($fh)<0;
     return if $doSender && !($SenderExtra & 4) && checkSender($fh)<0;
     checkSPF($fh) if $doSPF && !($SPFExtra & 4);
     return call('L4',checkRBL($fh)) if $doRBL && !($RBLExtra & 4); L4:
    }
   }
   return if checkNonLate($fh,0)<0;
   # rewrite sender address when relaying through Relay Host
   if ($CanUseSRS && $EnableSRS && $this->{isRelay} && !$this->{isbounce} && !(matchSL($this->{mailfrom},'noSRS'))) {
    ($tf)=();
    $srs=new Mail::SRS(Secret=>$SRSSecretKey,
                       MaxAge=>$SRSTimestampMaxAge,
                       HashLength=>$SRSHashLength,
                       AlwaysRewrite=>1);
    if (!eval{$tf=$srs->reverse($this->{mailfrom})} &&
         eval{$tf=$srs->forward($this->{mailfrom},$SRSAliasDomain)}) {
     $l=~s/\Q$this->{mailfrom}\E/$tf/;
    }
   }
   # for testing
   unless ($this->{isRelay}) {
    $this->{relayok}=($this->{relayok} && $this->{mailfrom} eq '') || $this->{mailfromlocal};
   }
  } elsif ($l=~/rcpt to: *(.*)/i) {
   $e=$1;
   ($u,$h)=();
   # enforce valid email address pattern
   if ($CanUseAddress && $DoRFC822) {
    if ($l=~/rcpt to:\s*<*([^\015\012>]*).*/i) {
     $RO_e=$1;
     if (!Email::Valid->address($RO_e)) {
      # couldn't understand recipient
      delayWhiteExpire($fh);
      return if checkRateLimit($fh,'rcptRelayRejected',1,0)<0;
      mlogCond($fh,"malformed address: '$RO_e'",1);
      sendque($fh,"553 Malformed address: $RO_e\015\012",1);
      checkMaxErrors($fh,'rcptRelayRejected',0,1);
      return;
     }
    }
   }
   if ($CanUseSRS && $EnableSRS) {
    ($ec)=$e=~/^<?([^\015\012>]*).*/;
    if (!$this->{isRelay} && $this->{isbounce}) {
     unless (matchSL($ec,'noSRS')) {
      # validate incoming bounces
      ($tt,$tt2)=();
      $srs=new Mail::SRS(Secret=>$SRSSecretKey,
                         MaxAge=>$SRSTimestampMaxAge,
                         HashLength=>$SRSHashLength,
                         AlwaysRewrite=>1);
      if ($ec=~/^SRS0[=+-].*/i) {
       if (eval{$tt=$srs->reverse($ec)}) {
        $l=~s/\Q$ec\E/$tt/;
        $e=<$tt>;
       } else {
        $this->{invalidSRSBounce}=1;
       }
      } elsif ($ec=~/^SRS1[=+-].*/i) {
       if (eval{$tt=$srs->reverse($ec)}) {
        if (eval{$tt2=$srs->reverse($tt)}) {
         $l=~s/\Q$ec\E/$tt2/;
         $e=<$tt2>;
        } else {
         return if checkRateLimit($fh,'rcptRelayRejected',1,0)<0;
         mlogCond($fh,"user not local; please try <$tt> directly",1);
         sendque($fh,"551 5.7.1 User not local; please try <$tt> directly\015\012",1);
         checkMaxErrors($fh,'rcptRelayRejected',1,0);
         return;
        }
       } else {
        $this->{invalidSRSBounce}=1;
       }
      } else {
       $this->{invalidSRSBounce}=1;
      }
     }
    } elsif (!$this->{isRelay} && $ec=~/^SRS[01][=+-].*/i) {
     return if checkRateLimit($fh,'rcptRelayRejected',1,0)<0;
     mlogCond($fh,"SRS only supported in DSN: $e",1);
     sendque($fh,"550 5.7.6 SRS only supported in DSN\015\012",1);
     checkMaxErrors($fh,'rcptRelayRejected',1,0);
     return;
    }
   }
   if ($e=~/[\!\%\@]\S*\@/) {
    # blatent attempt at relaying
    delayWhiteExpire($fh);
    return if checkRateLimit($fh,'rcptRelayRejected',1,0)<0;
    mlogCond($fh,"relay attempt blocked for (evil): $e",1);
    sendque($fh,"$NoRelaying\015\012",1);
    checkMaxErrors($fh,'rcptRelayRejected',0,1);
    return;
   } elsif ($e=~/([a-z\-_\.]+)!([a-z\-_\.]+)$/i) {
    # someone give me one good reason why I should support bang paths! grumble...
    $u="$2@";
    $h=$1;
   } elsif ($l=~/rcpt to:.*?($EmailAdrRe\@)($EmailDomainRe|\[(?:\d{1,3}\.){3}\d{1,3}\])/io) { # accept domain literals
    ($u,$h)=($1,$2);
   } elsif ($defaultLocalDomain && $l=~/rcpt to:.*?<($EmailAdrRe)>/io) {
    ($u,$h)=($1,$defaultLocalDomain);
    $u.='@';
   } else {
    # couldn't understand recipient
    delayWhiteExpire($fh);
    return if checkRateLimit($fh,'rcptRelayRejected',1,0)<0;
    mlogCond($fh,"relay attempt blocked for (parsing): $e",1);
    sendque($fh,"$NoRelaying\015\012",1);
    checkMaxErrors($fh,'rcptRelayRejected',0,1);
    return;
   }
   $rcptlocal=localMailDomain($h);
   if (!$this->{relayok} && (!$rcptlocal || ($u.$h)=~/\%/) || $u =~/\@\w+/) {
    delayWhiteExpire($fh);
    return if checkRateLimit($fh,'rcptRelayRejected',1,0)<0;
    mlogCond($fh,"relay attempt blocked for: $u$h",1);
    sendque($fh,"$NoRelaying\015\012",1);
    checkMaxErrors($fh,'rcptRelayRejected',0,1);
    return;
   }
   $rcptlocaladdress=0;
   if ($this->{relayok}) {
    # skip check when RELAYOK
    $rcptlocaladdress=$rcptlocal;
   } elsif (matchSL("$u$h",'LocalAddresses_Flat')) {
    # check recipient against flat list
    $rcptlocaladdress=1;
   } elsif ($CanUseLDAP && $DoLDAP) {
    # check recipient against LDAP
    return if ($rcptlocaladdress=checkLDAP($fh,$h))<0;
   } else {
    $rcptlocaladdress=$rcptlocal;
   }
   $this->{noprocessing}&=255-2 unless ($this->{noprocessing} & 2) && matchSL("$u$h",'noProcessing');
   $this->{addressedToSpamBucket}=1 if $rcptlocal && matchSL("$u$h",'spamaddresses');
   checkSpamLover($fh,"$u$h",$rcptlocal);
   return if checkEmailInterface($fh,$u,$rcptlocal)<0;
   # update some Sender Stats
   if ($SenderPosition==2 && ($SenderExtra & 4)) {
    if (!($SenderExtra & 1) && ($this->{noprocessing} & 3)) {
     mlogCond($fh,"sender noprocessing: $this->{mailfrom}",$SenderValLog);
     return if checkRateLimit($fh,'senderUnprocessed',0,0)<0;
     $Stats{senderUnprocessed}++;
    } elsif (!($SenderExtra & 2) && ($this->{mailfromonwl} || $this->{mWLDRE})) {
     mlogCond($fh,"sender whitelisted: $this->{mailfrom}",$SenderValLog);
     return if checkRateLimit($fh,'senderWhitelisted',0,0)<0;
     $Stats{senderWhitelisted}++;
    }
   }
   # normal (pre-data) checks, optimize checkRWL() position
   $doRateLimit=$EnableRateLimit && $RateLimitPosition==4 && (($RateLimitExtra & 1) || !($this->{noprocessing} & 3)) && (($RateLimitExtra & 2) || !($this->{mailfromonwl} || $this->{mWLDRE}));
   $doHelo=$ValidateHelo && $HeloPosition==3 && (($HeloExtra & 1) || !($this->{noprocessing} & 3)) && (($HeloExtra & 2) || !($this->{mailfromonwl} || $this->{mWLDRE}));
   $doSender=$ValidateSender && $SenderPosition==2 && (($SenderExtra & 1) || !($this->{noprocessing} & 3)) && (($SenderExtra & 2) || !($this->{mailfromonwl} || $this->{mWLDRE}));
   $doSPF=$CanUseSPF && $ValidateSPF && $SPFPosition==2 && (($SPFExtra & 1) || !($this->{noprocessing} & 3)) && (($SPFExtra & 2) || !($this->{mailfromonwl} || $this->{mWLDRE}));
   $doRBL=$CanUseRBL && $ValidateRBL && $RBLPosition==4 && (($RBLExtra & 1) || !($this->{noprocessing} & 3)) && (($RBLExtra & 2) || !($this->{mailfromonwl} || $this->{mWLDRE}));
   return if $doRateLimit && ($RateLimitExtra & 4) && checkRateLimitBlock($fh,1)<0;
   return if $doHelo && ($HeloExtra & 4) && checkHelo($fh,$this->{allLoveHlSpam})<0;
   return if $doSender && ($SenderExtra & 4) && checkSender($fh,$this->{allLoveMfSpam})<0;
   checkSPF($fh,$this->{allLoveSPFSpam}) if $doSPF && ($SPFExtra & 4);
   return call('L5',checkRBL($fh,$this->{allLoveRBLSpam})) if $doRBL && ($RBLExtra & 4); L5:
   if ($doRateLimit && !($RateLimitExtra & 4) ||
       $doHelo && !($HeloExtra & 4) ||
       $doSender && !($SenderExtra & 4) ||
       $doSPF && !($SPFExtra & 4) ||
       $doRBL && !($RBLExtra & 4)) {
    return call('L6',checkRWL($fh)); L6:
    # update some Sender Stats
    if ($SenderPosition==2 && !($SenderExtra & 4)) {
     if (!($SenderExtra & 1) && ($this->{noprocessing} & 3)) {
      mlogCond($fh,"sender noprocessing: $this->{mailfrom}",$SenderValLog);
      return if checkRateLimit($fh,'senderUnprocessed',0,0)<0;
      $Stats{senderUnprocessed}++;
     } elsif (!($SenderExtra & 2) && ($this->{mailfromonwl} || $this->{mWLDRE}) || $this->{rwlok}) {
      mlogCond($fh,"sender whitelisted: $this->{mailfrom}",$SenderValLog);
      return if checkRateLimit($fh,'senderWhitelisted',0,0)<0;
      $Stats{senderWhitelisted}++;
     }
    }
    unless ($this->{rwlok}) {
     return if $doRateLimit && !($RateLimitExtra & 4) && checkRateLimitBlock($fh,1)<0;
     return if $doHelo && !($HeloExtra & 4) && checkHelo($fh,$this->{allLoveHlSpam})<0;
     return if $doSender && !($SenderExtra & 4) && checkSender($fh,$this->{allLoveMfSpam})<0;
     checkSPF($fh,$this->{allLoveSPFSpam}) if $doSPF && !($SPFExtra & 4);
     return call('L7',checkRBL($fh,$this->{allLoveRBLSpam})) if $doRBL && !($RBLExtra & 4); L7:
    }
   }
   return if checkNonLate($fh,1)<0; ## ,1 fixme ??
   $this->{rcptValidated}=0;
   if ($this->{addressedToSpamBucket}) {
    # accept SpamBucket addresses in every case
    $this->{rcpt}.="$u$h ";
   } elsif ($LocalAddresses_Flat || $DoLDAP) {
    if ($rcptlocaladdress || $this->{relayok} && !$rcptlocal) {
     return if checkDelaying($fh,"$u$h")<0;
     mlogCond($fh,"recipient accepted: $u$h",$RecipientValLog);
     $this->{rcpt}.="$u$h ";
     $this->{rcptValidated}=1;
    } else {
     return if checkRateLimit($fh,'rcptNonexistent',1,1)<0;
     $err="nonexistent address rejected: $u$h";
     mlogCond($fh,$err,$RecipientValLog);
     slog($fh,"($err)",0,'I');
     $reply=$InvalidRecipientError ? $InvalidRecipientError : '550 5.1.1 User unknown';
     $reply=~s/EMAILADDRESS/$u$h/g;
     sendque($fh,"$reply\015\012",1);
     checkMaxErrors($fh,'rcptNonexistent',1,1);
     return;
    }
   } else {
    return if checkDelaying($fh,"$u$h")<0;
    mlogCond($fh,"recipient accepted unchecked: $u$h",$RecipientValLog);
    $this->{rcpt}.="$u$h ";
   }
   # update Stats
   if ($this->{noprocessing}) {
    return if checkRateLimit($fh,'rcptUnprocessed',0,1)<0;
    $Stats{rcptUnprocessed}++;
   } elsif ($this->{addressedToSpamBucket}) {
    return if checkRateLimit($fh,'rcptSpamBucket',0,1)<0;
    $Stats{rcptSpamBucket}++;
   } elsif ($this->{allLoveSpam}) {
    return if checkRateLimit($fh,'rcptSpamLover',0,1)<0;
    $Stats{rcptSpamLover}++;
   } elsif ($rcptlocal) {
    if ($this->{rcptValidated}) {
     return if checkRateLimit($fh,'rcptValidated',0,1)<0;
     $Stats{rcptValidated}++;
    } else {
     return if checkRateLimit($fh,'rcptUnchecked',0,1)<0;
     $Stats{rcptUnchecked}++;
    }
   } elsif ($Whitelist{lc "$u$h"}) {
    return if checkRateLimit($fh,'rcptWhitelisted',0,1)<0;
    $Stats{rcptWhitelisted}++;
   } else {
    return if checkRateLimit($fh,'rcptNotWhitelisted',0,1)<0;
    $Stats{rcptNotWhitelisted}++;
   }
  } elsif ($l=~/^ *XEXCH50 +(\d+)/i) {
   $this->{skipbytes}=$1;
  } elsif ($l=~/^ *(?:DATA|BDAT (\d+))/i) {
   if ($1) {
    $this->{bdata}=$1;
   } else {
    delete $this->{bdata};
   }
   $this->{rcpt}=~s/\s$//;
   # drop line if no recipients left
   if ($this->{rcpt}!~/@/) {
    # possible workaround for GroupWise bug
    if ($this->{delayed}) {
     return if checkRateLimit($fh,'msgDelayed',1,1)<0;
     mlogCond($fh,'DATA phase delayed',$DelayLog);
     $reply=$DelayError ? $DelayError : '451 4.7.1 Please try again later';
     sendque($fh,"$reply\015\012",1);
     doneStats($fh,0,'msgDelayed');
     return;
    }
    delayWhiteExpire($fh);
    return if checkRateLimit($fh,'msgNoRcpt',1,1)<0;
    mlogCond($fh,'no recipients left -- dropping connection',1);
    sendError($fh,'503 5.5.2 Need Recipient',0,'msgNoRcpt');
    return;
   }
   if (!$this->{isRelay} && $this->{isbounce} && $this->{delayed}) {
    return if checkRateLimit($fh,'msgDelayed',1,1)<0;
    mlogCond($fh,'bounce delayed',1);
    $reply=$DelayError ? $DelayError : '451 4.7.1 Please try again later';
    sendque($fh,"$reply\015\012",1);
    doneStats($fh,0,'msgDelayed');
    return;
   } else {
    $this->{getline}=\&preHeader;
   }
  } elsif ($l=~/^ *RSET/i) {
   stateReset($fh);
  }
  sendque($server,$l,1);
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub preHeader {
 my ($fh,$l);
 my ($this,$doRateLimit,$doMsgVerify);
 my $sref=$Tasks{$CurTaskID}->{preHeader}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  $this=$Con{$fh};
  # check for 5xx server response after the DATA command
  if ($this->{inerror}) {
   slog($fh,$l,0);
   sendque($this->{friend},$l,1);
   stateReset($fh);
   return;
  }
  $this->{indata}=1;
  # don't check, only log RateLimited connection addressed 
  # to RateLimit Spamlovers, optimize checkRWL() position
  # for checkLine() and checkHeader()
  $doRateLimit=$EnableRateLimit && (($RateLimitExtra & 1) || !($this->{noprocessing})) && (($RateLimitExtra & 2) || !($this->{mailfromonwl} || $this->{mWLDRE}));
  $doMsgVerify=(($MsgVerifyExtra & 1) || !($this->{noprocessing})) && (($MsgVerifyExtra & 2) || !($this->{mailfromonwl} || $this->{mWLDRE}));
  checkRateLimitBlock($fh,1) if $doRateLimit && ($RateLimitExtra & 4);
  if ($doRateLimit && !($RateLimitExtra & 4) ||
      $doMsgVerify && !($MsgVerifyExtra & 4)) {
   return call('L1',checkRWL($fh)); L1:
   unless ($this->{rwlok}) {
    checkRateLimitBlock($fh,1) if $doRateLimit && !($RateLimitExtra & 4);
   }
  }
  # prepare ClamAV STREAM connection
  return call('L2',prepareClamAV($fh)); L2:
  if ($this->{noprocessing}) {
   $this->{getline}=\&npHeader;
  } else {
   $this->{getline}=\&getHeader;
  }
  $sfh=$this->{sfh};
  # conduct late (post-header) checks
  return call('L3',$this->{getline}->($fh,$l)); L3:
 }];
 &{$sref->[0]};
 return $sref->[1];
}

# get the header part of the noprocessing DATA.
sub npHeader {
 my ($fh,$l);
 my ($this,$done);
 my $sref=$Tasks{$CurTaskID}->{npHeader}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  $this=$Con{$fh};
  return call('L1',checkVirus($fh,$l)); L1:
  $this->{header}.=$l;
  $this->{maillength}+=length($l);
  checkLine($fh,$l) if $MsgVerifyExtra & 1;
  $done=$l=~/^\.?(?:\015\012)?$/;
  if ($done || $this->{maillength}>=$MaxBytes) {
   splitFix($fh);
   return call('L2',npHeaderExec($fh,$l)); L2:
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

# get the header part of the DATA.
sub getHeader {
 my ($fh,$l);
 my ($this,$done,$onwl);
 my $sref=$Tasks{$CurTaskID}->{getHeader}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  $this=$Con{$fh};
  return call('L1',checkVirus($fh,$l)); L1:
  $this->{header}.=$l;
  $this->{maillength}+=length($l);
  checkLine($fh,$l) if (($MsgVerifyExtra & 2) || !($this->{mailfromonwl} || $this->{mWLDRE})) && (($MsgVerifyExtra & 4) || !$this->{rwlok});
  $done=$l=~/^\.?(?:\015\012)?$/;
  if ($done || $this->{maillength}>=$MaxBytes) {
   splitFix($fh);
   if ($npRe) {
    if ($this->{header}=~$npReRE) {
     mlogCond($fh,"header matches npRe: '$^R'",$RELog);
     $this->{noprocessing}|=4;
    } elsif ($this->{body}=~$npReRE) {
     mlogCond($fh,"body matches npRe: '$^R'",$RELog);
     $this->{noprocessing}|=8;
    }
   }
   ($onwl)=();
   if (!$this->{noprocessing} && ($onwl=checkWhitelist($fh)) && $npLwlRe) {
    if ($this->{header}=~$npLwlReRE) {
     mlogCond($fh,"header matches npLwlRe: '$^R'",$RELog);
     $this->{noprocessing}|=16;
    } elsif ($this->{body}=~$npLwlReRE) {
     mlogCond($fh,"body matches npLwlRe: '$^R'",$RELog);
     $this->{noprocessing}|=32;
    }
   }
   if ($this->{noprocessing}) {
    return call('L2',npHeaderExec($fh,$l)); L2:
   } elsif ($onwl) {
    return call('L3',wlHeaderExec($fh,$l)); L3:
   } else {
    return call('L4',getHeaderExec($fh,$l)); L4:
   }
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub splitFix {
 my $fh=shift;
 my $this=$Con{$fh};
 # split message into header and body
 ($this->{header},$this->{body})=$this->{header}=~/^(?:(.*?)(?:\015\015|\015\012\015\012|\012\012|\012\015)|)(.*)$/s;
 # fix malformed header but keep 'artifacts'
 my ($good,$all)=(0)x2;
 $good++ while $this->{header}=~/\015\012/g;
 $all++ while $this->{header}=~/\015?\012|\015/g;
 $this->{header}=~s/\015?\012|\015/\015\012/g if $all>2*$good;
 $this->{header}.="\015\012" if $this->{header};
}

sub npHeaderExec {
 my ($fh,$l);
 my $this;
 my $sref=$Tasks{$CurTaskID}->{npHeaderExec}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  $this=$Con{$fh};
  # update some Sender Stats
  if ($SenderPosition==3 && !($SenderExtra & 1)) {
   mlogCond($fh,"sender noprocessing: $this->{mailfrom}",$SenderValLog);
   return if checkRateLimit($fh,'senderUnprocessed',0,0)<0;
   $Stats{senderUnprocessed}++;
  }
  # late (post-header) checks
  return if $ValidateHelo && $HeloPosition==4 && ($HeloExtra & 1) && checkHelo($fh,$this->{allLoveHlSpam})<0;
  return if $ValidateSender && $SenderPosition==3 && ($SenderExtra & 1) && checkSender($fh,$this->{allLoveMfSpam})<0;
  checkSPF($fh,$this->{allLoveSPFSpam}) if $CanUseSPF && $ValidateSPF && $SPFPosition==3 && ($SPFExtra & 1);
  return call('L1',checkRBL($fh,$this->{allLoveRBLSpam})) if $CanUseRBL && $ValidateRBL && $RBLPosition==5 && ($RBLExtra & 1); L1:
  checkHeader($fh) if $MsgVerifyExtra & 1;
  if ($l=~/^\.(?:\015\012)?$/) {
   return call('L2',npBodyDone($fh,1)); L2:
  } else {
   $this->{getline}=\&npBody;
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub wlHeaderExec {
 my ($fh,$l);
 my ($this,$doHelo,$doSender,$doSPF,$doRBL);
 my $sref=$Tasks{$CurTaskID}->{wlHeaderExec}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  $this=$Con{$fh};
  # update some Sender Stats
  if ($SenderPosition==3 && !($SenderExtra & 6)) {
   mlogCond($fh,"sender whitelisted: $this->{mailfrom}",$SenderValLog);
   return if checkRateLimit($fh,'senderWhitelisted',0,0)<0;
   $Stats{senderWhitelisted}++;
  }
  # late (post-header) checks, optimize checkRWL() position
  $doHelo=$ValidateHelo && $HeloPosition==4;
  $doSender=$ValidateSender && $SenderPosition==3;
  $doSPF=$CanUseSPF && $ValidateSPF && $SPFPosition==3;
  $doRBL=$CanUseRBL && $ValidateRBL && $RBLPosition==5;
  return if $doHelo && ($HeloExtra & 6)==6 && checkHelo($fh,$this->{allLoveHlSpam})<0;
  return if $doSender && ($SenderExtra & 6)==6 && checkSender($fh,$this->{allLoveMfSpam})<0;
  checkSPF($fh,$this->{allLoveSPFSpam}) if $doSPF && ($SPFExtra & 6)==6;
  return call('L1',checkRBL($fh,$this->{allLoveRBLSpam})) if $doRBL && ($RBLExtra & 6)==6; L1:
  if ($doHelo && (($HeloExtra & 6)==2 || ($HeloExtra & 6)==4) ||
      $doSender && (($SenderExtra & 6)==2 || ($SenderExtra & 6)==4) ||
      $doSPF && (($SPFExtra & 6)==2 || ($SPFExtra & 6)==4) ||
      $doRBL && (($RBLExtra & 6)==2 || ($RBLExtra & 6)==4)) {
   return call('L2',checkRWL($fh)); L2:
   # update some Sender Stats
   if ($SenderPosition==3 && (($SenderExtra & 2) && $this->{rwlok} || ($SenderExtra & 4) && !$this->{rwlok})) {
    mlogCond($fh,"sender whitelisted: $this->{mailfrom}",$SenderValLog);
    return if checkRateLimit($fh,'senderWhitelisted',0,0)<0;
    $Stats{senderWhitelisted}++;
   }
   return if $doHelo && (($HeloExtra & 2) && !$this->{rwlok} || ($HeloExtra & 4) && $this->{rwlok}) && checkHelo($fh,$this->{allLoveHlSpam})<0;
   return if $doSender && (($SenderExtra & 2) && !$this->{rwlok} || ($SenderExtra & 4) && $this->{rwlok}) && checkSender($fh,$this->{allLoveMfSpam})<0;
   checkSPF($fh,$this->{allLoveSPFSpam}) if $doSPF && (($SPFExtra & 2) && !$this->{rwlok} || ($SPFExtra & 4) && $this->{rwlok});
   return call('L3',checkRBL($fh,$this->{allLoveRBLSpam})) if $doRBL && (($RBLExtra & 2) && !$this->{rwlok} || ($RBLExtra & 4) && $this->{rwlok}); L3:
  }
  checkHeader($fh) if ($MsgVerifyExtra & 6)==6 || ($MsgVerifyExtra & 2) && !$this->{rwlok} || ($MsgVerifyExtra & 4) && $this->{rwlok};
  if ($l=~/^\.(?:\015\012)?$/) {
   return call('L4',whiteBodyDone($fh,1)); L4:
  } else {
   $this->{getline}=\&whiteBody;
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub getHeaderExec {
 my ($fh,$l);
 my ($this,$doHelo,$doSender,$doSPF,$doRBL);
 my $sref=$Tasks{$CurTaskID}->{getHeaderExec}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  $this=$Con{$fh};
  # late (post-header) checks, optimize checkRWL() position
  $doHelo=$ValidateHelo && $HeloPosition==4;
  $doSender=$ValidateSender && $SenderPosition==3;
  $doSPF=$CanUseSPF && $ValidateSPF && $SPFPosition==3;
  $doRBL=$CanUseRBL && $ValidateRBL && $RBLPosition==5;
  checkBlacklist($fh);
  return if $doHelo && ($HeloExtra & 4) && checkHelo($fh,$this->{allLoveHlSpam})<0;
  return if $doSender && ($SenderExtra & 4) && checkSender($fh,$this->{allLoveMfSpam})<0;
  checkSpamBucket($fh);
  checkSRSBounce($fh);
  checkSPF($fh,$this->{allLoveSPFSpam}) if $doSPF && ($SPFExtra & 4);
  return call('L1',checkRBL($fh,$this->{allLoveRBLSpam})) if $doRBL && ($RBLExtra & 4); L1:
  if ($doHelo && !($HeloExtra & 4) ||
      $doSender && !($SenderExtra & 4) ||
      $doSPF && !($SPFExtra & 4) ||
      $doRBL && !($RBLExtra & 4)) {
   return call('L2',checkRWL($fh)); L2:
   # update some Sender Stats
   if ($SenderPosition==3 && !($SenderExtra & 4) && $this->{rwlok}) {
    mlogCond($fh,"sender whitelisted: $this->{mailfrom}",$SenderValLog);
    return if checkRateLimit($fh,'senderWhitelisted',0,0)<0;
    $Stats{senderWhitelisted}++;
   }
   unless ($this->{rwlok}) {
    return if $doHelo && !($HeloExtra & 4) && checkHelo($fh,$this->{allLoveHlSpam})<0;
    return if $doSender && !($SenderExtra & 4) && checkSender($fh,$this->{allLoveMfSpam})<0;
    checkSPF($fh,$this->{allLoveSPFSpam}) if $doSPF && !($SPFExtra & 4);
    return call('L3',checkRBL($fh,$this->{allLoveRBLSpam})) if $doRBL && !($RBLExtra & 4); L3:
   }
  }
  checkHeader($fh) if ($MsgVerifyExtra & 4) || !$this->{rwlok};
  if ($l=~/^\.(?:\015\012)?$/) {   
   return call('L4',getBodyDone($fh,1)); L4:
  } else {
   $this->{getline}=\&getBody;
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub npBody {
 my ($fh,$l);
 my ($this,$done);
 my $sref=$Tasks{$CurTaskID}->{npBody}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  $this=$Con{$fh};
  return call('L1',checkVirus($fh,$l)); L1:
  $this->{body}.=$l;
  $this->{maillength}+=length($l);
  checkLine($fh,$l) if $MsgVerifyExtra & 1;
  $done=$l=~/^\.(?:\015\012)?$/ || defined($this->{bdata}) && $this->{bdata}<=0;
  if ($done || $this->{maillength}>=$MaxBytes) {
   # late (post-body) checks
   return if $ValidateHelo && $HeloPosition==5 && ($HeloExtra & 1) && checkHelo($fh,$this->{allLoveHlSpam})<0;
   return if $ValidateSender && $SenderPosition==4 && ($SenderExtra & 1) && checkSender($fh,$this->{allLoveMfSpam})<0;
   checkSPF($fh,$this->{allLoveSPFSpam}) if $CanUseSPF && $ValidateSPF && $SPFPosition==4 && ($SPFExtra & 1);
   return call('L2',checkRBL($fh,$this->{allLoveRBLSpam})) if $CanUseRBL && $ValidateRBL && $RBLPosition==6 && ($RBLExtra & 1); L2:
   checkAttach($fh,'(noprocessing)',$BlockNPExes,$npAttachColl);
   return call('L3',checkURIBL($fh)) if $CanUseURIBL && $ValidateURIBL && $URIBLExtra & 1; L3:
   return call('L4',npBodyDone($fh,$done)); L4:
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub whiteBody {
 my ($fh,$l);
 my ($this,$done,$doHelo,$doSender,$doSPF,$doRBL,$doURIBL);
 my $sref=$Tasks{$CurTaskID}->{whiteBody}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  $this=$Con{$fh};
  return call('L1',checkVirus($fh,$l)); L1:
  $this->{body}.=$l;
  $this->{maillength}+=length($l);
  checkLine($fh,$l) if ($MsgVerifyExtra & 6)==6 || ($MsgVerifyExtra & 2) && !$this->{rwlok} || ($MsgVerifyExtra & 4) && $this->{rwlok};
  $done=$l=~/^\.(?:\015\012)?$/ || defined($this->{bdata}) && $this->{bdata}<=0;
  if ($done || $this->{maillength}>=$MaxBytes) {
   if ($this->{body}=~$npReRE) {
    mlogCond($fh,"body matches npRe: '$^R'",$RELog);
    $this->{noprocessing}|=8;
   } elsif ($this->{body}=~$npLwlReRE) {
    mlogCond($fh,"body matches npLwlRe: '$^R'",$RELog);
    $this->{noprocessing}|=32;
   }
   $doHelo=$ValidateHelo && $HeloPosition==5;
   $doSender=$ValidateSender && $SenderPosition==4;
   $doSPF=$CanUseSPF && $ValidateSPF && $SPFPosition==4;
   $doRBL=$CanUseRBL && $ValidateRBL && $RBLPosition==6;
   $doURIBL=$CanUseURIBL && $ValidateURIBL;
   if ($this->{noprocessing}) {
    # late (post-body) checks
    return if $doHelo && ($HeloExtra & 1) && checkHelo($fh,$this->{allLoveHlSpam})<0;
    return if $doSender && ($SenderExtra & 1) && checkSender($fh,$this->{allLoveMfSpam})<0;
    checkSPF($fh,$this->{allLoveSPFSpam}) if $doSPF && ($SPFExtra & 1);
    return call('L2',checkRBL($fh,$this->{allLoveRBLSpam})) if $doRBL && ($RBLExtra & 1); L2:
    checkAttach($fh,'(noprocessing)',$BlockNPExes,$npAttachColl);
    return call('L3',checkURIBL($fh)) if $doURIBL && ($URIBLExtra & 1); L3:
    return call('L4',npBodyDone($fh,$done)); L4:
   } else {
    # late (post-body) checks, optimize checkRWL() position
    return if $doHelo && ($HeloExtra & 6)==6 && checkHelo($fh,$this->{allLoveHlSpam})<0;
    return if $doSender && ($SenderExtra & 6)==6 && checkSender($fh,$this->{allLoveMfSpam})<0;
    checkSPF($fh,$this->{allLoveSPFSpam}) if $doSPF && ($SPFExtra & 6)==6;
    return call('L5',checkRBL($fh,$this->{allLoveRBLSpam})) if $doRBL && ($RBLExtra & 6)==6; L5:
    if ($doHelo && (($HeloExtra & 6)==2 || ($HeloExtra & 6)==4) ||
        $doSender && (($SenderExtra & 6)==2 || ($SenderExtra & 6)==4) ||
        $doSPF && (($SPFExtra & 6)==2 || ($SPFExtra & 6)==4) ||
        $doRBL && (($RBLExtra & 6)==2 || ($RBLExtra & 6)==4)) {
     return call('L6',checkRWL($fh)); L6:
     # update some Sender Stats
     if ($SenderPosition==4 && (($SenderExtra & 2) && $this->{rwlok} || ($SenderExtra & 4) && !$this->{rwlok})) {
      mlogCond($fh,"sender whitelisted: $this->{mailfrom}",$SenderValLog);
      return if checkRateLimit($fh,'senderWhitelisted',0,0)<0;
      $Stats{senderWhitelisted}++;
     }
     return if $doHelo && (($HeloExtra & 2) && !$this->{rwlok} || ($HeloExtra & 4) && $this->{rwlok}) && checkHelo($fh,$this->{allLoveHlSpam})<0;
     return if $doSender && (($SenderExtra & 2) && !$this->{rwlok} || ($SenderExtra & 4) && $this->{rwlok}) && checkSender($fh,$this->{allLoveMfSpam})<0;
     checkSPF($fh,$this->{allLoveSPFSpam}) if $doSPF && (($SPFExtra & 2) && !$this->{rwlok} || ($SPFExtra & 4) && $this->{rwlok});
     return call('L7',checkRBL($fh,$this->{allLoveRBLSpam})) if $doRBL && (($RBLExtra & 2) && !$this->{rwlok} || ($RBLExtra & 4) && $this->{rwlok}); L7:
    }
    checkAttach($fh,'(local/white)',$BlockWLExes,$wlAttachColl);
    return call('L8',checkURIBL($fh)) if $doURIBL && ($URIBLExtra & 6)==6; L8:
    if ($doURIBL && (($URIBLExtra & 6)==2 || ($URIBLExtra & 6)==4)) {
     return call('L9',checkRWL($fh)); L9:
     return call('L10',checkURIBL($fh)) if $doURIBL && (($URIBLExtra & 2) && !$this->{rwlok} || ($URIBLExtra & 4) && $this->{rwlok}); L10:
    }
    return call('L11',whiteBodyDone($fh,$done)); L11:
   }
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

# the message may or may not be spam -- get the body and test it.
sub getBody {
 my ($fh,$l);
 my ($this,$done,$doHelo,$doSender,$doSPF,$doRBL,$doURIBL);
 my $sref=$Tasks{$CurTaskID}->{getBody}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  $this=$Con{$fh};
  return call('L1',checkVirus($fh,$l)); L1:
  $this->{body}.=$l;
  $this->{maillength}+=length($l);
  checkLine($fh,$l) if ($MsgVerifyExtra & 4) || !$this->{rwlok};
  $done=$l=~/^\.(?:\015\012)?$/ || defined($this->{bdata}) && $this->{bdata}<=0;
  if ($done || $this->{maillength}>=$MaxBytes) {
   if ($this->{body}=~$npReRE) {
    mlogCond($fh,"body matches npRe: '$^R'",$RELog);
    $this->{noprocessing}|=8;
   }
   $doHelo=$ValidateHelo && $HeloPosition==5;
   $doSender=$ValidateSender && $SenderPosition==4;
   $doSPF=$CanUseSPF && $ValidateSPF && $SPFPosition==4;
   $doRBL=$CanUseRBL && $ValidateRBL && $RBLPosition==6;
   $doURIBL=$CanUseURIBL && $ValidateURIBL;
   if ($this->{noprocessing}) {
    # late (post-body) checks
    return if $doHelo && ($HeloExtra & 1) && checkHelo($fh,$this->{allLoveHlSpam})<0;
    return if $doSender && ($SenderExtra & 1) && checkSender($fh,$this->{allLoveMfSpam})<0;
    checkSPF($fh,$this->{allLoveSPFSpam}) if $doSPF && ($SPFExtra & 1);
    return call('L2',checkRBL($fh,$this->{allLoveRBLSpam})) if $doRBL && ($RBLExtra & 1); L2:
    checkAttach($fh,'(noprocessing)',$BlockNPExes,$npAttachColl);
    return call('L3',checkURIBL($fh)) if $doURIBL && ($URIBLExtra & 1); L3:
    return call('L4',npBodyDone($fh,$done)); L4:
   } else {
    # late (post-body) checks, optimize checkRWL() position
    return if $doHelo && ($HeloExtra & 4) && checkHelo($fh,$this->{allLoveHlSpam})<0;
    return if $doSender && ($SenderExtra & 4) && checkSender($fh,$this->{allLoveMfSpam})<0;
    checkSPF($fh,$this->{allLoveSPFSpam}) if $doSPF && ($SPFExtra & 4);
    return call('L5',checkRBL($fh,$this->{allLoveRBLSpam})) if $doRBL && ($RBLExtra & 4); L5:
    if ($doHelo && !($HeloExtra & 4) ||
        $doSender && !($SenderExtra & 4) ||
        $doSPF && !($SPFExtra & 4) ||
        $doRBL && !($RBLExtra & 4)) {
     return call('L6',checkRWL($fh)); L6:
     # update some Sender Stats
     if ($SenderPosition==4 && !($SenderExtra & 4) && $this->{rwlok}) {
      mlogCond($fh,"sender whitelisted: $this->{mailfrom}",$SenderValLog);
      return if checkRateLimit($fh,'senderWhitelisted',0,0)<0;
      $Stats{senderWhitelisted}++;
     }
     unless ($this->{rwlok}) {
      return if $doHelo && !($HeloExtra & 4) && checkHelo($fh,$this->{allLoveHlSpam})<0;
      return if $doSender && !($SenderExtra & 4) && checkSender($fh,$this->{allLoveMfSpam})<0;
      checkSPF($fh,$this->{allLoveSPFSpam}) if $doSPF && !($SPFExtra & 4);
      return call('L7',checkRBL($fh,$this->{allLoveRBLSpam})) if $doRBL && !($RBLExtra & 4); L7:
     }
    }
    checkBomb($fh);
    checkScript($fh);
    checkAttach($fh,'(external)',$BlockExes,$extAttachColl);
    return call('L8',checkURIBL($fh)) if $doURIBL && ($URIBLExtra & 4); L8:
    if ($doURIBL && !($URIBLExtra & 4)) {
     return call('L9',checkRWL($fh)); L9:
     unless ($this->{rwlok}) {
      return call('L10',checkURIBL($fh)) if $doURIBL && !($URIBLExtra & 4); L10:
     }
    }
    checkSpam($fh);
    return call('L11',getBodyDone($fh,$done)); L11:
   }
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub npBodyDone {
 my ($fh,$done);
 my ($this,$checked);
 my $sref=$Tasks{$CurTaskID}->{npBodyDone}||=[sub{
  ($fh,$done)=@_;
 },sub{&jump;
  $this=$Con{$fh};
  $checked=$this->{checkedattach};
  $checked=",$checked" if $checked;
  if ($this->{spamfound}) {
   return call('L1',passSpam($fh,"safe spam (noprocessing$checked)",$done)); L1:
  } else {
   return call('L2',passHam($fh,"message ok (noprocessing$checked)",$npColl,'noprocessing',$done)); L2:
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub whiteBodyDone {
 my ($fh,$done);
 my ($this,$checked);
 my $sref=$Tasks{$CurTaskID}->{whiteBodyDone}||=[sub{
  ($fh,$done)=@_;
 },sub{&jump;
  $this=$Con{$fh};
  $checked=$this->{checkedattach};
  $checked=",$checked" if $checked;
  if ($this->{spamfound}) {
   if ($this->{relayok}) {
    return call('L1',passSpam($fh,"safe spam (local$checked)",$done)); L1:
   } else {
    return call('L2',passSpam($fh,"safe spam (whitelisted$checked)",$done)); L2:
   }
  } else {
   if ($this->{relayok}) {
    if ($this->{red}) {
     return call('L3',passHam($fh,"message ok (local,redlisted$checked)",$redColl,'reds',$done)); L3:
    } else {
     return call('L4',passHam($fh,"message ok (local$checked)",$localColl,'locals',$done)); L4:
    }
   } else {
    if ($this->{red}) {
     return call('L5',passHam($fh,"message ok (whitelisted,redlisted$checked)",$redColl,'reds',$done)); L5:
    } else {
     return call('L6',passHam($fh,"message ok (whitelisted$checked)",$whiteColl,'whites',$done)); L6:
    }
   }
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub getBodyDone {
 my ($fh,$done);
 my ($this,$checked);
 my $sref=$Tasks{$CurTaskID}->{getBodyDone}||=[sub{
  ($fh,$done)=@_;
 },sub{&jump;
  $this=$Con{$fh};
  $checked=$this->{checkedattach};
  $checked=",$checked" if $checked;
  if ($this->{spamfound}) {
   return call('L1',passSpam($fh,"safe spam (external$checked)",$done)); L1:
  } else {
   if ($this->{red}) {
    return call('L2',passHam($fh,"message ok (external,redlisted$checked)",$redColl,'reds',$done)); L2:
   } else {
    return call('L3',passHam($fh,"message ok (external$checked)",$baysNonSpamColl,'bhams',$done)); L3:
   }
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

# this is spam, lets see if its test mode or spamlover.
sub thisIsSpam {
 my ($fh,$reason,$error,$testmode,$spamlover,$coll,$stats,$prob)=@_;
 my $this=$Con{$fh};
 $this->{stats}=$this->{tag}=$stats;
 $this->{error}=$error;
 $this->{spamprob}=$prob;
 if (checkNeeded($fh,$coll,$testmode,$spamlover)) {
  $this->{coll}=$coll;
  if ($AddSpamReasonHeader) {
   if ($this->{myheader}=~/^X-Assp-Spam-Reason$HeaderSepRe/imo) {
    $this->{myheader}=~s/^(X-Assp-Spam-Reason$HeaderSepValueRe)/$1, $reason/gimo;
   } else {
    $this->{myheader}.='X-Assp-Spam-Reason: '.ucfirst($reason)."\015\012";
   }
  }
  slog($fh,'('.($this->{indata} ? needEs($this->{maillength},' byte','s').' received; ' : '')."$reason)",0,'I');
 }
 if ($this->{spamfound} & 4) {
  mlogCond($fh,$reason,1);
 } elsif ($spamlover) {
  mlogCond($fh,"passing because spamlover(s): $this->{rcpt}, otherwise $reason",1) if $this->{indata};
  delayWhiteExpire($fh) unless $this->{allLoveNoDelaying};
  $this->{stats}='spamlover';
  $this->{spamfound}|=1; # set spamlover bit in spamfound flag
 } elsif ($testmode) {
  mlogCond($fh,"passing because testmode, otherwise $reason",1) if $this->{indata};
  delayWhiteExpire($fh);
  $this->{stats}='testspams';
  $this->{spamfound}|=2; # set testmode bit in spamfound flag
 } else {
  mlogCond($fh,$reason,1);
  delayWhiteExpire($fh);
  # detatch the friend -- closing connection to server & disregarding message
  doneConnection($this->{friend},1);
  $this->{spamfound}|=4; # set spam bit in spamfound flag
 }
}

# the message is not spam, route it to the server
sub passHam {
 my ($fh,$reason,$coll,$stats,$done);
 my $this;
 my $sref=$Tasks{$CurTaskID}->{passHam}||=[sub{
  ($fh,$reason,$coll,$stats,$done)=@_;
 },sub{&jump;
  $this=$Con{$fh};
  $this->{coll}=$coll;
  $this->{stats}=$this->{tag}=$stats;
  $this->{mlogbuf}=$reason;
  return call('L1',pass($fh,$done)); L1:
 }];
 &{$sref->[0]};
 return $sref->[1];
}

# the message is spam, route it to the server
sub passSpam {
 my ($fh,$reason,$done);
 my $this;
 my $sref=$Tasks{$CurTaskID}->{passSpam}||=[sub{
  ($fh,$reason,$done)=@_;
 },sub{&jump;
  $this=$Con{$fh};
  $this->{mlogbuf}=$reason;
  return call('L1',pass($fh,$done)); L1:
 }];
 &{$sref->[0]};
 return $sref->[1];
}

# create tmp file for the body of the message
sub prepareTmpBody {
 my $fh=shift;
 my $this=$Con{$fh};
 my $sfh=$this->{sfh};
 $SMTPSessions{$sfh}->{tmpfn}="tmp/$SMTPSessions{$sfh}->{id}_$SMTPSessions{$sfh}->{msgcnt}";
 $SMTPSessions{$sfh}->{tmpfh}=IO::File->new(">$base/$SMTPSessions{$sfh}->{tmpfn}");
 binmode($SMTPSessions{$sfh}->{tmpfh});
}

# write into message body tmp file
sub addTmpBody {
 my ($fh,$l)=@_;
 my $this=$Con{$fh};
 print {$SMTPSessions{$this->{sfh}}->{tmpfh}} $l;
}

# close and/or unlink message body tmp file
# param = 2 bits flag specifying actions to be taken
sub doneTmpBody {
 my ($fh,$param)=@_;
 my $this=$Con{$fh};
 my $sfh=$this->{sfh};
 if (($param & 1) && $SMTPSessions{$sfh}->{tmpfh}) {
  close $SMTPSessions{$sfh}->{tmpfh};
  delete $SMTPSessions{$sfh}->{tmpfh};
 }
 if (($param & 2) && $SMTPSessions{$sfh}->{tmpfn}) {
  unlink("$base/$SMTPSessions{$sfh}->{tmpfn}");
  delete $SMTPSessions{$sfh}->{tmpfn};
 }
}

sub pass {
 my ($fh,$done);
 my ($this,$sf,$skip,$rcvdh,$header,$sub,$e,$tt,$tt2,$srs,$h);
 my $sref=$Tasks{$CurTaskID}->{pass}||=[sub{
  ($fh,$done)=@_;
 },sub{&jump;
  $this=$Con{$fh};
  $sf=$this->{spamfound};
  $skip=$this->{noprocessing} && !$sf || $NoExternalSpamProb && $this->{relayok};
  ($rcvdh)=();
  unless ($skip) {
   # preserve received X-ASSP headers
   while ($this->{header}=~/^(X-Assp-$HeaderAllRe)/gimo) {
    $rcvdh.="$1; " unless $1=~/^X-Assp-Received-Headers$HeaderSepRe/io;
   }
   $rcvdh=~s/\015\012[ \t]+/ /g; # unwrap them
   # clear out received ASSP headers
   $this->{header}=~s/^X-Assp-$HeaderAllCRLFRe//gimo;
  }
  # always add our Received: header
  # preserve original header
  $header=$this->{header}=$this->{rcvd}.$this->{header};
  unless ($skip) {
   # add From: if missing
   if ($header!~/^From$HeaderSepRe/imo) {
    $header.="From: sender not supplied\015\012";
   }
   # add Subject: if missing
   if ($header!~/^Subject$HeaderSepRe/imo) {
    $header.="Subject: \015\012";
   }
   # add spamSubject to Subject: if needed
   if ($sf && ($spamSubjectSL || !($sf & 1))) {
    $sub=$spamSubject;
    $sub=~s/TAG/$SubjectTags{$this->{tag}}/g;
    if ($sub && $header!~/^Subject$HeaderSepRe\Q$sub\E /im) {
     $header=~s/^Subject$HeaderSepRe/Subject: $sub /gimo; # rewrite all Subject: headers
    }
   }
   # rewrite To: header in bounces
   if ($CanUseSRS && $EnableSRS && $SRSRewriteToHeader && !$this->{isRelay} && $this->{isbounce}) {
    if (($e)=$header=~/^To$HeaderSepRe($HeaderValueRe)/imo) {
     ($tt,$tt2)=();
     $srs=new Mail::SRS(Secret=>$SRSSecretKey,
                        MaxAge=>$SRSTimestampMaxAge,
                        HashLength=>$SRSHashLength,
                        AlwaysRewrite=>1);
     if ($e=~/<?(SRS0[=+-][^\015\012>]*).*/i) {
      if (eval{$tt=$srs->reverse($1)}) {
       $e=~s/\Q$1\E/$tt/;
      }
     } elsif ($e=~/^<?(SRS1[=+-][^\015\012>]*).*/i) {
      if (eval{$tt=$srs->reverse($1)} && eval{$tt2=$srs->reverse($tt)}) {
       $e=~s/\Q$1\E/$tt2/;
      }
     }
     $header=~s/^To$HeaderSepValueRe/To: $e/imo;
    }
   }
   $this->{myheader}.="X-Assp-Received-Headers: $rcvdh\015\012" if $rcvdh;
   $this->{myheader}.="X-Assp-Spam: YES\015\012" if $AddSpamHeader && $sf;
   $this->{myheader}.=sprintf("X-Assp-Spam-Prob: %.5f\015\012",$this->{spamprob}) if $AddSpamProbHeader;
   $this->{myheader}.="X-Assp-Whitelisted: Yes\015\012" if $this->{white};
   $this->{myheader}.="X-Assp-Redlisted: Yes\015\012" if $this->{red};
   $this->{myheader}.="X-Assp-Envelope-From: $this->{mailfrom}\015\012" if defined($this->{mailfrom});
   # wrap long header lines
   headerWrap($this->{myheader});
   # sort & merge our header with client's one
   foreach $h (@MyHeaders) {
    $header.=$1 if $this->{myheader}=~/^(X-Assp-\Q$h\E$HeaderSepValueCRLFRe)/m;
   }
  }
  sendque($this->{friend},"$header\015\012");
  prepareTmpBody($fh);
  # send/store body
  if ($done) {
   return call('L1',finalizeMail($fh,$this->{body})); L1:
   return if (shift)<0;
  } else {
   $this->{getline}=\&continueBody;
   sendque($this->{friend},$this->{body});
   addTmpBody($fh,$this->{body});
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

# inlined and partially unrolled for speed
sub continueBody {
 my ($fh,$l);
 my ($this,$bn,$len,$done);
 my $sref=$Tasks{$CurTaskID}->{continueBody}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  $this=$Con{$fh};

  $this->{skipcheckLine}||=($MsgVerifyExtra & 1) && $this->{noprocessing} ||

   !$MsgVerifyWL && $this->{white};

  return call('L1',checkVirus($fh,$l)) unless $this->{skipcheckVirus}; L1:
  $this->{maillength}+=length($l);
  checkLine($fh,$l) unless $this->{skipcheckLine};
  $done=$l=~/^\.(?:\015\012)?$/ || defined($this->{bdata}) && $this->{bdata}<=0;
  if ($done) {
   return call('L2',finalizeMail($fh,$l)); L2:
   return if (shift)<0;
  } else {
   sendque($this->{friend},$l);
   addTmpBody($fh,$l);
  }
  # it's possible that the connection can be deleted
  # while there's still something in the buffer
  return unless $Con{$fh}; # '$this' may be not valid -- check $Con{$fh}
  while (($bn=index($this->{_},"\015\012"))>=0) {
   $bn+=2; # crlf length
   $l=substr($this->{_},0,$bn,''); # four-argument substr()
   $len=length($l);
   addTrafStats($fh,$len,0);
   $this->{bdata}-=$len if defined($this->{bdata});
   return call('L3',checkVirus($fh,$l)) unless $this->{skipcheckVirus}; L3:
   $this->{maillength}+=$len;
   checkLine($fh,$l) unless $this->{skipcheckLine};
   $done=$l=~/^\.(?:\015\012)?$/ || defined($this->{bdata}) && $this->{bdata}<=0;
   if ($done) {
    return call('L4',finalizeMail($fh,$l)); L4:
    return if (shift)<0;
   } else {
    sendque($this->{friend},$l);
    addTmpBody($fh,$l);
   }
   # it's possible that the connection can be deleted
   # while there's still something in the buffer
   last unless $Con{$fh}; # '$this' may be not valid -- check $Con{$fh}
  }
  # '$this' may be not valid -- check $Con{$fh} instead
  if ($Con{$fh}) {
   $len=length($this->{_});
   if ($len>$MaxBytes) {
    addTrafStats($fh,$len,0);
    $this->{bdata}-=$len if defined($this->{bdata});
    return call('L5',checkVirus($fh,$this->{_})) unless $this->{skipcheckVirus}; L5:
    $this->{maillength}+=$len;
    checkLine($fh,$this->{_}) unless $this->{skipcheckLine};
    $done=$this->{_}=~/^\.(?:\015\012)?$/ || defined($this->{bdata}) && $this->{bdata}<=0;
    if ($done) {
     return call('L6',finalizeMail($fh,$this->{_})); L6:
     return if (shift)<0;
    } else {
     sendque($this->{friend},$this->{_});
     addTmpBody($fh,$this->{_});
    }
    $this->{_}='' if $Con{$fh}; # '$this' may be not valid -- check $Con{$fh} instead
   }
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub finalizeMail {
 my ($fh,$l);
 my ($this,$sfh,$sf);
 my $sref=$Tasks{$CurTaskID}->{finalizeMail}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  $this=$Con{$fh};
  $sfh=$this->{sfh};
  $SMTPSessions{$sfh}->{msgcnt}++;
  addTmpBody($fh,$l);
  doneTmpBody($fh,1); # close tmp message body file
  return call('L1',checkClamAV($fh)); L1:
  slog($fh,'('.needEs($this->{maillength},' byte','s').' received; end of data)',0,'I');
  $sf=$this->{spamfound};
  return -1 if $this->{stats} && checkRateLimit($fh,$this->{stats},1,1)<0;
  if ($sf & 4) {
   return -1 if checkRateLimit($fh,'msgAnyBlockedSpam',1,1)<0;
  } elsif ($sf) {
   return -1 if checkRateLimit($fh,'msgAnyPassedSpam',1,1)<0;
  } else {
   return -1 if checkRateLimit($fh,'msgAnyHam',0,1)<0;
  }
  unless ($this->{isRelay}) {
   $logCount[$this->{coll}]++;
   if ($logCount[$this->{coll}]>=$logFreq[$this->{coll}]) {
    $logCount[$this->{coll}]=0;
    unless ($this->{simulating}) {
     # fix {myheader} if spam was found after MaxBytes has been reached
     unless ($this->{noprocessing} && !$sf || $NoExternalSpamProb && $this->{relayok}) {
      # clear out some existing headers
      $this->{myheader}=~s/^X-Assp-Spam$HeaderSepValueCRLFRe//gimo;
      $this->{myheader}=~s/^X-Assp-Spam-Prob$HeaderSepValueCRLFRe//gimo;
      # add corrected headers
      $this->{myheader}.="X-Assp-Spam: YES\015\012" if $AddSpamHeader && $sf;
      $this->{myheader}.=sprintf("X-Assp-Spam-Prob: %.5f\015\012",$this->{spamprob}) if $AddSpamProbHeader;
     }
     collectMail($fh);
 ##    forwardSpam($fh);
    }
   }
  }
  if ($sf & 4) {
   # ignore what was sent & give reason at the end
   sendError($fh,$this->{error});
   return 0;
  }
  mlogCond($fh,$this->{mlogbuf},1);
  sendque($this->{friend},$l) unless $this->{simulating};
  doneStats($fh,1);
  doneTmpBody($fh,2); # unlink tmp message body file
  doneClamAV($fh,3); # close COMMAND & STREAM
  stateReset($fh);
  return 1;
 }];
 &{$sref->[0]};
 return $sref->[1];
}

# reject the email
sub sendError {
 my ($fh,$error,$quiet,$stats)=@_;
 my $this=$Con{$fh};
 if ($error) {
  print $fh "$error\015\012" unless $quiet;
  slog($fh,$error,1);
 } else {
  slog($fh,'(empty error reply string)',1);
 }
 doneStats($fh,0,$stats);
 doneSession($fh,1);
}

# filter off the 250 OK noop response and go to reply
sub skipok {
 my ($fh,$l)=@_;
 if ($l=~/^250/) {
  $Con{$fh}->{getline}=\&reply;
  slog($fh,"$l (in response to NOOP)",0,'S');
 } else {
  reply(@_);
 }
}

# messages from the server get relayed to the client
sub reply {
 my ($fh,$l);
 my ($this,$client,$e,$err,$reply,$delay,$buf,$len,$ip,$port,$doRateLimit,$doRBL);
 my $sref=$Tasks{$CurTaskID}->{reply}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  $this=$Con{$fh};
  $client=$this->{friend};
  $Con{$client}->{inenvelope}=1;
  slog($fh,$l,0);
  $Con{$client}->{inerror}=$l=~/^(?:550|50[0-9])/;
  if ($DetectInvalidRecipient && $l=~/$DetectInvalidRecipient/i) {
   return if checkRateLimit($client,'rcptNonexistent',1,0)<0;
   # drop last recipient
   $Con{$client}->{rcpt}=~s/(.*?)[^ ]+ ?$/$1/;
   ($e)=$l=~/($EmailAdrRe\@$EmailDomainRe)/o;
   $err="nonexistent address detected: $e";
   mlogCond($client,$err,$RecipientValLog);
   slog($client,"($err)",0,'I');
   $reply=$InvalidRecipientError ? $InvalidRecipientError : '550 5.1.1 User unknown';
   $reply=~s/EMAILADDRESS/$e/g;
   sendque($client,"$reply\015\012",1);
   $Stats{rcptUnchecked}-- if $Stats{rcptUnchecked}>0;
   checkMaxErrors($client,'rcptNonexistent',1,1);
   return;
  } elsif ($l=~/250-(?:CHUNKING|PIPELINING)/i) {
   # we'll filter off the chunking directive to avoid BDAT problems.
   return;
  } elsif ($l=~/250-XEXCH50/i) {
   # we'll filter off the XEXCH50 service, as it only causes troubles
   return;
  } elsif ($l=~/250-.*STARTTLS/i) {
   # we'll filter off the STARTTLS directive to avoid TLS problems.
   return;
  } elsif ($l=~/^220/) {
   # proxy client IP to server in NOOP command
   if ($this->{noop}) {
    sendque($fh,$this->{noop},1);
    delete $this->{noop};
   }

   return call('L4',checkRWL($client)); L4: ## testing

##   # early (on-connect) checks
##   return if $RateLimitPosition==1 && checkRateLimitBlock($client,0)<0;
##   return call('L1',checkRBL($client)) if $RBLPosition==1; L1:
##   return if checkNonLate($client,0)<0;

   # early (on-connect) checks, optimize checkRWL() position
   $doRateLimit=$EnableRateLimit && $RateLimitPosition==1;
   $doRBL=$CanUseRBL && $ValidateRBL && $RBLPosition==1;
   return if $doRateLimit && ($RateLimitExtra & 4) && checkRateLimitBlock($client,0)<0;
   return call('L1',checkRBL($client)) if $doRBL && ($RBLExtra & 4); L1:
   if ($doRateLimit && !($RateLimitExtra & 4) ||
       $doRBL && !($RBLExtra & 4)) {
    return call('L2',checkRWL($client)); L2:
    unless ($Con{$client}->{rwlok}) {
     return if $doRateLimit && !($RateLimitExtra & 4) && checkRateLimitBlock($client,0)<0;
     return call('L3',checkRBL($client)) if $doRBL && !($RBLExtra & 4); L3:
    }
   }
   return if checkNonLate($client,0)<0;

   # detect earlytalkers
   unless ($this->{greetdelay}<0) {
    $delay=$this->{greetdelay};
    # handle multiline banners
    $this->{greetdelay}=-1;
    resumeTask($Con{$client}->{itid});
    waitTaskRead(0,$client,$delay);
    return cede('L4'); L4:
    if (getTaskWaitResult(0)) {
     if ($client->sysread($buf,4096)>0) {
      $len=length($buf);
      addTrafStats($client,$len,0);
      # peek at the spontaneous client
      slog($client,$buf,0);
      delayWhiteExpire($client);
      return if checkRateLimit($client,'msgEarlytalker',0,0)<0;
      $ip=$Con{$client}->{ip};
      $port=$Con{$client}->{port};
      mlogCond($client,'earlytalker ('.needEs($len,' byte','s').')',$ConnectionLog && !$Con{$client}->{mNLOGRE});
      $Con{$client}->{stats}='msgEarlytalker';
      sendError($client,$GreetDelayError);
      return;
     } else {
      # client disconnected while we were waiting for input
     }
     return;
    }
   }

##   # early (pre-banner) checks
##   return if $RateLimitPosition==2 && checkRateLimitBlock($client,0)<0;
##   return call('L5',checkRBL($client)) if $RBLPosition==2; L5:
##   return if checkNonLate($client,0)<0;

   # early (pre-banner) checks, optimize checkRWL() position
   $doRateLimit=$EnableRateLimit && $RateLimitPosition==2;
   $doRBL=$CanUseRBL && $ValidateRBL && $RBLPosition==2;
   return if $doRateLimit && ($RateLimitExtra & 4) && checkRateLimitBlock($client,0)<0;
   return call('L5',checkRBL($client)) if $doRBL && ($RBLExtra & 4); L5:
   if ($doRateLimit && !($RateLimitExtra & 4) ||
       $doRBL && !($RBLExtra & 4)) {
    return call('L6',checkRWL($client)); L6:
    unless ($Con{$client}->{rwlok}) {
     return if $doRateLimit && !($RateLimitExtra & 4) && checkRateLimitBlock($client,0)<0;
     return call('L7',checkRBL($client)) if $doRBL && !($RBLExtra & 4); L7:
    }
   }
   return if checkNonLate($client,0)<0;

  } elsif ($l=~/^235/) {
   # check for authentication response
   mlogCond($client,'authenticated',$ClientValLog);
   $Con{$client}->{relayok}=1;
  } elsif ($l=~/^354/) {
  } elsif ($l=~/^(?:550|50[0-9])/) {
   if ($Con{$client}->{skipbytes}) {
    $Con{$client}->{skipbytes}=0; # if we got a negative response from XEXCH50 then don't skip anything
   }
   return if checkMaxErrors($client,'',1,1)<0;
  }
  # email report/list interface sends messages itself
  return if (defined($Con{$client}->{reporttype}) && $Con{$client}->{reporttype}>=0);
  sendque($client,$l,1);
 }];
 &{$sref->[0]};
 return $sref->[1];
}

#####################################################################################
#                Checks functions

# returns true if this address is local
sub localMailDomain {
 my $h=shift;
 $h=$1 if $h=~/\@(.*)/;
 return 1 if $h=~$LDRE;
 if ($localDomainsFile) {
  check4update(localDomainsFile);
  return 1 if $localDomainsFile{lc $h};
 }
 return 0;
}

sub checkLDAP {
 my ($fh,$h)=@_;
 my $this=$Con{$fh};
 my ($retcode,$retmsg);
 $h=$1 if $h=~/\@(.*)/;
 # do LDAP lookup
 my $current_email="$1$h";
 my $ldapflt=$LDAPFilter;
 $ldapflt=~s/EMAILADDRESS/$current_email/g;
 my $ldap;
 for (my $i=@ldaplist;$i>0;$i--) {
  $ldap=Net::LDAP->new($ldaplist[0],timeout=>10);
  last if $ldap;
  if ($#ldaplist>0 && $i>1) {
   mlogCond($fh,"couldn't contact LDAP server ($ldaplist[0]) -- trying another ($ldaplist[1])",1);
   push(@ldaplist,shift(@ldaplist));
  }
 }
 unless ($ldap) {
  mlogCond($fh,'couldn\'t contact any of LDAP servers -- aborting connection',1);
  sendError($fh,'451 Could not check address, try later');
  return -1;
 }
 my $mesg;
 # bind to a directory anonymous or with dn and password
 if ($LDAPLogin) {
  $mesg=$ldap->bind($LDAPLogin,password => $LDAPPassword);
 } else {
  # mlogCond($fh,'LDAP anonymous bind',1);
  $mesg=$ldap->bind;
 }
 $retcode=$mesg->code;
 if ($retcode) {
  # $retmsg=$mesg->error_text();
  # mlogCond($fh,"LDAP bind error: $retcode - Login Problem?",1);
  mlogCond($fh,"LDAP bind error: $retcode -- aborting connection",1);
  sendError($fh,'451 Could not check recipient, try later');
  return -1;
 }
 # perform a search
 $mesg=$ldap->search(base => $LDAPRoot,filter => $ldapflt,attrs => ['cn']);
 $retcode=$mesg->code;
 # mlogCond($fh,"LDAP search: $retcode",1);
 if ($retcode>0) {
  mlogCond($fh,"LDAP search error: $retcode -- aborting connection",1);
  sendError($fh,'451 Could not check recipient, try later');
  return -1;
 }
 my $entry_count=$mesg->count;
 $retmsg=$mesg->entry(1);
 # mlogCond($fh,"LDAP Results: $entry_count : $retmsg",1);
 $mesg=$ldap->unbind;  # take down session
 return $entry_count;
}

sub checkNeeded {
 my ($fh,$coll,$testmode,$spamlover)=@_;
 my $this=$Con{$fh};
 return $coll>$this->{coll} || !(($this->{spamfound} & 4) || $testmode || $spamlover);
}

sub checkNonLate {
 my ($fh,$spamlover)=@_;
 my $this=$Con{$fh};
 # any failures from non-late checks?
 if ($this->{spamfound} & 4) {
  return -1 if $this->{stats} && checkRateLimit($fh,$this->{stats},1,$spamlover)<0;
  return -1 if checkRateLimit($fh,'msgAnyBlockedSpam',1,$spamlover)<0;
  sendError($fh,$this->{error});
  return -1;
 }
 return 1;
}

# see if the address in the mailfrom is on the whitelist meanwhile update the whitelist if that seems appropriate
sub checkWhitelist {
 my $fh=shift;
 my $this=$Con{$fh};
 my $a=lc $this->{mailfrom};
 my $whitelisted=$this->{relayok} || $this->{rwlok};
## return $whitelisted unless $a; # don't add to the whitelist unless there's a valid envelope -- prevent bounced mail from adding to the whitelist
 return $whitelisted if $this->{isbounce}; # don't add to the whitelist unless there's a valid envelope -- prevent bounced mail from adding to the whitelist
 if ($Redlist{$a}) {
  mlogCond($fh,'sender on redlist',$SenderValLog);
  $this->{red}=1;
 } elsif ($redRe) {
  if ($this->{header}=~$redReRE) {
   mlogCond($fh,"header matches redRe: '$^R'",$RELog);
   $this->{red}=1;
  } elsif ($this->{body}=~$redReRE) {
   mlogCond($fh,"body matches redRe: '$^R'",$RELog);
   $this->{red}=1;
  }
 }
 my %senders;
 unless ($whitelisted) {
  $senders{$a}=1;
  unless ($NotGreedyWhitelist) {
   while ($this->{header}=~/^(?:From|Sender|Reply-To|Errors-To|List-$HeaderNameRe)$HeaderSepRe($HeaderValueRe)/gimo) {
    my $v=$1;
    while ($v=~/($EmailAdrRe\@$EmailDomainRe)/go) {
     $senders{lc $1}=1;
    }
   }
  }
  foreach $a (keys %senders) {
   return 0 if $a && $Redlist{$a};
   next if localMailDomain($a) || $a eq '';
   if ($a=~('('.$WLDRE.')')) {
    $whitelisted=1;
    mlogCond($fh,"matches whiteListedDomainsRe: '$1'",$RELog);
    last;
   } elsif ($Whitelist{$a}) {
    $whitelisted=1;
    last;
   }
  }
  $this->{senders}=join(' ',keys %senders).' '; # used for finding blacklisted domains
  $this->{white}=$whitelisted;
 }
 # don't add to whitelist if sender is redlisted
 return $whitelisted if $this->{red} || $WhitelistLocalOnly && !$this->{relayok};
 if ($whitelisted) {
  # keep the whitelist up-to-date
  my %a=%senders;
  my $t=time;
  $a{$a}=1;
  while ($this->{header}=~/^(?:To|Cc)$HeaderSepRe($HeaderValueRe)/gimo) {
   my $v=$1;
   while ($v=~/($EmailAdrRe\@$EmailDomainRe)/go) {
    $a{lc $1}=1;
   }
  }
  foreach $a (split(' ',lc $this->{rcpt})) {
   $a{$a}=1;
  }
  foreach $a (keys %a) {
   next if localMailDomain($a) || !$a;
   next if $a=~$WLDRE;
   if ($Whitelist{$a}) {
    unless ($this->{simulating}) {
     my ($added,$updated)=split("\003",$Whitelist{$a});
     $updated=$t-$added; # time delta
     $Whitelist{$a}="$added\003$updated";
    }
   } else {
    mlogCond($fh,"whitelist addition: $a",1);
    $Whitelist{$a}=$t unless $this->{simulating};
   }
  }
  return 1;
 }
 return 0;
}

sub checkBlacklist {
 my $fh=shift;
 my $this=$Con{$fh};
 return if $this->{relayok} || $this->{mISPRE};
 return unless checkNeeded($fh,$blDomainColl,$blTestMode,$this->{allLoveBlSpam});
 return unless $this->{mailfrom}=~$BLDRE1 || $this->{senders}=~$BLDRE2;
 thisIsSpam($fh,'blacklisted domain',$SpamError,$blTestMode,$this->{allLoveBlSpam},$blDomainColl,'blacklisted',1);
}

sub checkSpamLover {
 my ($fh,$a,$rcptlocal)=@_;
 my $this=$Con{$fh};
 my $mSLRE=matchSL($a,'spamLovers');
 my $mHLSLRE=matchSL($a,'hlSpamLovers');
 my $mMFSLRE=matchSL($a,'mfSpamLovers');
 my $mBLSLRE=matchSL($a,'blSpamLovers');
 my $mDELSLRE=matchSL($a,'delayingSpamLovers');
 my $mSPFSLRE=matchSL($a,'spfSpamLovers');
 my $mRBLSLRE=matchSL($a,'rblSpamLovers');
 my $mSRSSLRE=matchSL($a,'srsSpamLovers');
 my $mMVSLRE=matchSL($a,'msgVerifySpamLovers');
 my $mBOSLRE=matchSL($a,'bombsSpamLovers');
 my $mURIBLSLRE=matchSL($a,'uriblSpamLovers');
 my $mBSLRE=matchSL($a,'baysSpamLovers');
 my $mRLSLRE=matchSL($a,'ratelimitSpamLovers');
 $this->{allLoveSpam}=0 unless $rcptlocal && ($mSLRE || $mBSLRE || $mBLSLRE || $mHLSLRE || $mSPFSLRE || $mRBLSLRE || $mSRSSLRE || $mURIBLSLRE || $mDELSLRE || $mMVSLRE || $mMFSLRE || $mBOSLRE || $mRLSLRE);
 $this->{allLoveHlSpam}=0 unless $rcptlocal && ($mHLSLRE || $mSLRE);
 $this->{allLoveMfSpam}=0 unless $rcptlocal && ($mMFSLRE || $mSLRE);
 $this->{allLoveBlSpam}=0 unless $rcptlocal && ($mBLSLRE || $mSLRE);
 $this->{allLoveNoDelaying}=0 unless $rcptlocal && ($mDELSLRE || $mSLRE);
 $this->{allLoveSPFSpam}=0 unless $rcptlocal && ($mSPFSLRE || $mSLRE);
 $this->{allLoveRBLSpam}=0 unless $rcptlocal && ($mRBLSLRE || $mSLRE);
 $this->{allLoveSRSSpam}=0 unless $rcptlocal && ($mSRSSLRE || $mSLRE);
 $this->{allLoveMalformedSpam}=0 unless $rcptlocal && ($mMVSLRE || $mSLRE);
 $this->{allLoveBombsSpam}=0 unless $rcptlocal && ($mBOSLRE || $mSLRE);
 $this->{allLoveURIBLSpam}=0 unless $rcptlocal && ($mURIBLSLRE || $mSLRE);
 $this->{allLoveBaysSpam}=0 unless $rcptlocal && ($mBSLRE || $mSLRE);
 $this->{allLoveRateLimitSpam}=0 unless $rcptlocal && ($mRLSLRE || $mSLRE);
}

sub checkEmailInterface {
 my ($fh,$u,$rcptlocal)=@_;
 my $this=$Con{$fh};
 return 0 unless $EmailInterfaceOk && $this->{relayok} && $rcptlocal;
 return 0 if $this->{simulating};
 if (lc $u eq lc "$EmailSpam\@") {
  return -1 if checkRateLimit($fh,'rcptReportSpam',0,1)<0;
  $this->{reporttype}=0;
  $this->{getline}=\&spamReport;
  mlog($fh,'email spamreport') if $EmailInterfaceLog;
  sendque($fh,"250 OK\015\012",1);
  $Stats{rcptReportSpam}++;
  return -1;
 } elsif (lc $u eq lc "$EmailHam\@") {
  return -1 if checkRateLimit($fh,'rcptReportHam',0,1)<0;
  $this->{reporttype}=1;
  $this->{getline}=\&spamReport;
  mlog($fh,'email hamreport') if $EmailInterfaceLog;
  sendque($fh,"250 OK\015\012",1);
  $Stats{rcptReportHam}++;
  return -1;
 } elsif (lc $u eq lc "$EmailWhitelistAdd\@") {
  return -1 if checkRateLimit($fh,'rcptReportWhitelistAdd',0,1)<0;
  $this->{reporttype}=2;
  $this->{getline}=\&listReport;
  mlog($fh,'email whitelist addition') if $EmailInterfaceLog;
  foreach my $a (split(/ /,$this->{rcpt})) {listReportExec($fh,$a);}
  sendque($fh,"250 OK\015\012",1);
  $Stats{rcptReportWhitelistAdd}++;
  return -1;
 } elsif (lc $u eq lc "$EmailWhitelistRemove\@") {
  return -1 if checkRateLimit($fh,'rcptReportWhitelistRemove',0,1)<0;
  $this->{reporttype}=3;
  $this->{getline}=\&listReport;
  mlog($fh,'email whitelist deletion') if $EmailInterfaceLog;
  foreach my $a (split(/ /,$this->{rcpt})) {listReportExec($fh,$a);}
  sendque($fh,"250 OK\015\012",1);
  $Stats{rcptReportWhitelistRemove}++;
  return -1;
 } elsif (lc $u eq lc "$EmailRedlistAdd\@") {
  return -1 if checkRateLimit($fh,'rcptReportRedlistAdd',0,1)<0;
  $this->{reporttype}=4;
  $this->{getline}=\&listReport;
  mlog($fh,'email redlist addition') if $EmailInterfaceLog;
  foreach my $a (split(/ /,$this->{rcpt})) {listReportExec($fh,$a);}
  sendque($fh,"250 OK\015\012",1);
  $Stats{rcptReportRedlistAdd}++;
  return -1;
 } elsif (lc $u eq lc "$EmailRedlistRemove\@") {
  return -1 if checkRateLimit($fh,'rcptReportRedlistRemove',0,1)<0;
  $this->{reporttype}=5;
  $this->{getline}=\&listReport;
  mlog($fh,'email redlist deletion') if $EmailInterfaceLog;
  foreach my $a (split(/ /,$this->{rcpt})) {listReportExec($fh,$a);}
  sendque($fh,"250 OK\015\012",1);
  $Stats{rcptReportRedlistRemove}++;
  return -1;
 }
 return 0;
}

sub checkHelo {
 my ($fh,$spamlover)=@_;
 my $this=$Con{$fh};
 return if $this->{relayok} || $this->{mISPRE};
## return unless $ValidateHelo;
 my $result=1;
 if (@{$this->{Helocache}}) {
  ($result)=@{$this->{Helocache}};
 } else {
  my $skip;
  unless (checkNeeded($fh,$spamHeloColl,$hlTestMode,$spamlover)) {
   $skip=1;
  }
  unless ($skip) {
   if (matchIP($this->{ip},'noHelo')) {
    mlogCond($fh,"client helo check skipped (noHelo IP): $this->{helo}",$ClientValLog);
   } else {
    my ($literal)=$this->{helo}=~/\[((?:\d{1,3}\.){3}\d{1,3})\]/; # domain literal
    if ($this->{helo}=~$hlSpamReRE) {
     mlogCond($fh,"helo matches hlSpamRe: '$^R'",$RELog);
     mlogCond($fh,"client helo spam: $this->{helo}",$ClientValLog);
     $Stats{clientHeloSpam}++;
     $result=0;
    } else {
     if ($HeloForged) {
      if ($this->{helo}=~$LHNRE || $literal=~$LHNRE || $this->{helo}=~$LDRE) {
       $result=0;
      } elsif ($localDomainsFile) {
       check4update(localDomainsFile);
       $result=0 if $localDomainsFile{lc $this->{helo}};
      }
     }
     unless ($result) {
      mlogCond($fh,"client helo forged: $this->{helo}",$ClientValLog);
      $Stats{clientHeloForged}++;
     } elsif ($HeloBlacklist && $HeloBlackObject && $HeloBlack{$this->{helo}}) {
      mlogCond($fh,"client helo blacklisted: $this->{helo}",$ClientValLog);
      $Stats{clientHeloBlacklisted}++;
      $result=0;
     } else {
      if ($HeloMismatch) {
       if ($literal && $literal ne $this->{ip}) {
        $result=0;
       } elsif ($CanUseDNS) {
        my ($ip2)=$this->{ip}=~/(.*)(?:\.\d+){2}$/;
        $ip2=~s/\./\\\./g; # make re out of ip2
        my $res=Net::DNS::Resolver->new;
        my $sock=$res->bgsend($this->{helo});
        until ($res->bgisready($sock)) {
         MainLoop();
        }
        my $packet=$res->bgread($sock);
        my @answer=$packet->answer;
        $result=0;
        foreach my $a (@answer) {
         if ($a->rdatastr=~/^$ip2/) {
          $result=1;
          last;
         }
        }
       }
      }
      unless ($result) {
       mlogCond($fh,"client helo mismatch: $this->{helo}",$ClientValLog);
       $Stats{clientHeloMismatch}++;
      }
     }
    }
   }
  }
  @{$this->{Helocache}}=($result);
  # update Stats
  if ($skip) {
   mlogCond($fh,"client helo accepted unchecked: $this->{helo}",$ClientValLog) unless $this->{spamfound};
   return -1 if checkRateLimit($fh,'clientHeloUnchecked',0,$spamlover)<0;
   $Stats{clientHeloUnchecked}++;
  } elsif ($result) {
   mlogCond($fh,"client helo validated: $this->{helo}",$ClientValLog);
   return -1 if checkRateLimit($fh,'clientHeloValidated',0,$spamlover)<0;
   $Stats{clientHeloValidated}++;
  }
 }
 unless ($result) {
  thisIsSpam($fh,'spam helo',$SpamError,$hlTestMode,$spamlover,$spamHeloColl,'helolisted',1);
 }
 return $result;
}

sub checkSender {
 my ($fh,$spamlover)=@_;
 my $this=$Con{$fh};
 return 1 if $this->{relayok} || $this->{mISPRE};
## return 1 unless $ValidateSender;
 return 1 unless checkNeeded($fh,$mfFailColl,$mfTestMode,$spamlover);
 my $result=1;
 if (@{$this->{Sendercache}}) {
  ($result)=@{$this->{Sendercache}};
 } else {
  my $skip;
  if (matchSL($this->{mailfrom},'noSenderCheck')) {
   mlogCond($fh,"sender check skipped (noSenderCheck): $this->{mailfrom}",$SenderValLog);
   $skip=1;
  }
  unless ($skip) {
   if ($this->{mailfromlocal}) {
    if ($SenderForged && $LocalAddresses_Flat && !matchSL($this->{mailfrom},'LocalAddresses_Flat')) {
     $result=0;
    } elsif ($CanUseLDAP && $SenderLDAP) {
     return -1 if ($result=checkLDAP($fh,$this->{mailfrom}))<0;
    }
    unless ($result) {
     mlogCond($fh,"sender forged (local): $this->{mailfrom}",$SenderValLog);
     return -1 if checkRateLimit($fh,'senderForged',0,$spamlover)<0;
     $Stats{senderForged}++;
    }
   } elsif ($CanUseDNS && $SenderMX && !$this->{isbounce}) {
    my ($u,$h)=$this->{mailfrom}=~/($EmailAdrRe\@)($EmailDomainRe)/o;
    $h=~s/\s+//g;
    $h=~s/(^\[)|(\]$)//g; # remove brackets if it's a domain literal
    my $res=Net::DNS::Resolver->new;
    my $sock=$res->bgsend($h,'A');
    until ($res->bgisready($sock)) {
     MainLoop();
    }
    my $packet=$res->bgread($sock);
    unless ($packet->header->ancount) {
     $sock=$res->bgsend($h,'MX');
     until ($res->bgisready($sock)) {
      MainLoop();
     }
     $packet=$res->bgread($sock);
     $result=0 unless $packet->header->ancount;
    }
    ($sock)=();
    unless ($result) {
     mlogCond($fh,"sender nonexistent MX (remote): $this->{mailfrom}",$SenderValLog);
     return -1 if checkRateLimit($fh,'senderNoMX',0,$spamlover)<0;
     $Stats{senderNoMX}++;
    }
   }
  }
  @{$this->{Sendercache}}=($result);
  # update Stats
  if ($skip) {
   if ($this->{mailfromlocal}) {
    mlogCond($fh,"sender accepted unchecked (local): $this->{mailfrom}",$SenderValLog) unless $this->{spamfound};
    return -1 if checkRateLimit($fh,'senderUncheckedLocal',0,$spamlover)<0;
    $Stats{senderUnchecked}++;
   } else {
    mlogCond($fh,"sender accepted unchecked (remote): $this->{mailfrom}",$SenderValLog) unless $this->{spamfound};
    return -1 if checkRateLimit($fh,'senderUncheckedRemote',0,$spamlover)<0;
    $Stats{senderUncheckedRemote}++;
   }
  } elsif ($result) {
   if ($this->{mailfromlocal}) {
    mlogCond($fh,"sender validated (local): $this->{mailfrom}",$SenderValLog);
    return -1 if checkRateLimit($fh,'senderValidatedLocal',0,$spamlover)<0;
    $Stats{senderValidatedLocal}++;
   } else {
    mlogCond($fh,"sender validated (remote): $this->{mailfrom}",$SenderValLog);
    return -1 if checkRateLimit($fh,'senderValidatedRemote',0,$spamlover)<0;
    $Stats{senderValidatedRemote}++;
   }
  }
 }
 unless ($result) {
  thisIsSpam($fh,'invalid sender',$SpamError,$mfTestMode,$spamlover,$mfFailColl,'senderfails',1);
 }
 return $result;
}

sub checkSpamBucket {
 my $fh=shift;
 my $this=$Con{$fh};
 return if $this->{relayok} || $this->{mISPRE};
 return unless $this->{addressedToSpamBucket};
 return unless checkNeeded($fh,$spamBucketColl,$sbTestMode,$this->{allLoveSpam});
 thisIsSpam($fh,'spam trap',$SpamError,$sbTestMode,$this->{allLoveSpam},$spamBucketColl,'spambucket',1);
}

sub checkSRSBounce {
 my $fh=shift;
 my $this=$Con{$fh};
 return if $this->{relayok} || $this->{mISPRE};
 return unless $CanUseSRS && $EnableSRS;
 return unless $SRSValidateBounce && $this->{invalidSRSBounce};
 return unless checkNeeded($fh,$SRSFailColl,$srsTestMode,$this->{allLoveSRSSpam});
 return if matchIP($this->{ip},'noSRSBounce');
 thisIsSpam($fh,'not SRS signed',$SRSBounceError,$srsTestMode,$this->{allLoveSRSSpam},$SRSFailColl,'msgNoSRSBounce',1);
}

# do SPF (sender policy framework) checks
sub checkSPF {
 my ($fh,$spamlover)=@_;
 my $this=$Con{$fh};
 return if $this->{relayok} || $this->{mISPRE};
## return unless $CanUseSPF && $ValidateSPF;
 my ($per_result,$smtp_comment);
 if (@{$this->{SPFcache}}) {
  ($per_result,$smtp_comment)=@{$this->{SPFcache}};
 } else {
  my $skip;
  my $ip=$this->{ip};
  unless (checkNeeded($fh,$SPFFailColl,$spfTestMode,$spamlover)) {
   mlogCond($fh,"SPF lookup skipped (unnecessary)",$SPFLog);
   $skip=1;
  } elsif (matchIP($ip,'noSPF')) {
   mlogCond($fh,"SPF lookup skipped (noSPF IP)",$SPFLog);
   $this->{myheader}.="X-Assp-Received-SPF: lookup skipped (noSPF IP); client-ip=$ip\015\012" if $AddSPFHeader;
   $skip=1;
  }
  unless ($skip) {
   my $query=new Mail::SPF::Query(ipv4       => $ip,
                                  sender     => $this->{mailfrom},
                                  helo       => $this->{helo},
                                  trusted    => 1,
                                  guess      => $LocalPolicySPF,
                                  myhostname => $myName,
                                  sanitize   => 1,
                                  debug      => $DebugSPF,
                                  debuglog   => sub { mlog($fh,"debug: @_") });
   my $header_comment;
   if ($SPFPosition<3) {
    # no recipients at this stage
    $Stats{providerQueriesSPF}++;
    my $time=Time::HiRes::time() if $AvailHiRes;
    ($per_result,$smtp_comment,$header_comment)=$query->result();
    if ($AvailHiRes) {
     $time=Time::HiRes::time()-$time;
     $Stats{providerTimeSPF}+=$time;
     $Stats{providerMinTimeSPF}=$time if $time<$Stats{providerMinTimeSPF} || !$Stats{providerMinTimeSPF};
     $Stats{providerMaxTimeSPF}=$time if $time>$Stats{providerMaxTimeSPF};
    }
   } else {
    foreach my $recip (split(' ', $this->{rcpt})) {
     $Stats{providerQueriesSPF}++;
     my $time=Time::HiRes::time() if $AvailHiRes;
     ($per_result,$smtp_comment,$header_comment)=$query->result2($recip);
     if ($AvailHiRes) {
      $time=Time::HiRes::time()-$time;
      $Stats{providerTimeSPF}+=$time;
      $Stats{providerMinTimeSPF}=$time if $time<$Stats{providerMinTimeSPF} || !$Stats{providerMinTimeSPF};
      $Stats{providerMaxTimeSPF}=$time if $time>$Stats{providerMaxTimeSPF};
     }
     # Keep processing SPF records until all recipients are checked otherwise breakout if fail
     last if $per_result eq 'fail';
    }
   }
   my $received_spf;
   $received_spf="Received-SPF: $per_result ($header_comment) client-ip=$ip";
   $received_spf.="; envelope-from=$this->{mailfrom}" if (defined($this->{mailfrom}));
   $received_spf.="; helo=$this->{helo}" if (defined($this->{helo}));
   mlogCond($fh,$received_spf,$SPFLog);
   $this->{myheader}.="X-Assp-$received_spf\015\012" if $AddSPFHeader;
  }
  @{$this->{SPFcache}}=($per_result,$smtp_comment);
 }
 if ($per_result eq 'fail') {
  # This email fails SPF rules for the sending domain. Apply SPF Failure Rules
  my $err=$SPFError;
  $err=~s/COMMENT/$smtp_comment/g;
  thisIsSpam($fh,'failed SPF checks',$err,$spfTestMode,$spamlover,$SPFFailColl,'spffails',1);
 }
}

# do RWL checks
sub checkRWL {
 my $fh;
 my ($this,$rwls_returned,@listed_by,$skip,$ip,$rwl,$received_rwl,$time,$err);
 my $sref=$Tasks{$CurTaskID}->{checkRWL}||=[sub{
  $fh=shift;
 },sub{&jump;
  $this=$Con{$fh};
  return if $this->{relayok} || $this->{mISPRE};
  return unless $CanUseRWL && $ValidateRWL;
  ($rwls_returned,@listed_by)=();
  if (@{$this->{RWLcache}}) {
   ($rwls_returned,@listed_by)=@{$this->{RWLcache}};
  } else {
   ($skip)=();
   $ip=$this->{ip};

##   unless (checkNeeded($fh,$RBLFailColl,$rblTestMode,$spamlover)) {
##    mlogCond($fh,"RBL lookup skipped (unnecessary)",$RBLLog);
##    $skip=1;
##   } elsif (matchIP($ip,'noRWL')) {

   if (matchIP($ip,'noRWL')) {
    mlogCond($fh,"RWL lookup skipped (noRWL IP)",$RBLLog);
    $this->{myheader}.="X-Assp-Received-RWL: lookup skipped (noRWL IP); client-ip=$ip\015\012" if $AddRWLHeader;
    $skip=1;
   }
   unless ($skip) {
    $rwl=RBL->new(lists       => [@rwllist],
                  server      => $nameservers[0],
                  max_hits    => $RWLminhits,
                  max_replies => $RWLmaxreplies,
                  query_txt   => 0,
                  max_time    => $RWLmaxtime,
                  timeout     => 1);
    ($received_rwl)=();
    $Stats{providerQueriesRWL}++;
    $time=Time::HiRes::time() if $AvailHiRes;
    return call('L1',$rwl->lookup($fh,$ip)); L1:
    if ($AvailHiRes) {
     $time=Time::HiRes::time()-$time;
     $Stats{providerTimeRWL}+=$time;
     $Stats{providerMinTimeRWL}=$time if $time<$Stats{providerMinTimeRWL} || !$Stats{providerMinTimeRWL};
     $Stats{providerMaxTimeRWL}=$time if $time>$Stats{providerMaxTimeRWL};
    }
    @listed_by=$rwl->listed_by();
    $rwls_returned=$#listed_by+1;
    if ($rwls_returned>=$RWLminhits) {
     $received_rwl="Received-RWL: pass ($myName: local policy) rwl=@listed_by; client-ip=$ip";
    } elsif ($rwls_returned>0) {
     $received_rwl="Received-RWL: neutral ($myName: local policy) rwl=@listed_by; client-ip=$ip";
    } else {
     $received_rwl="Received-RWL: fail ($myName: local policy) rwl=none; client-ip=$ip";
    }
    mlogCond($fh,$received_rwl,$RBLLog);
    $this->{myheader}.="X-Assp-$received_rwl\015\012" if $AddRWLHeader;
   }
   @{$this->{RWLcache}}=($rwls_returned,@listed_by);
  }

  $this->{rwlok}=1 if $rwls_returned>=$RWLminhits;

 }];
 &{$sref->[0]};
 return $sref->[1];
}

# do RBL checks
sub checkRBL {
 my ($fh,$spamlover);
 my ($this,$rbls_returned,@listed_by,$skip,$ip,$rbl,$received_rbl,$time,$err);
 my $sref=$Tasks{$CurTaskID}->{checkRBL}||=[sub{
  ($fh,$spamlover)=@_;
 },sub{&jump;
  $this=$Con{$fh};
  return if $this->{relayok} || $this->{mISPRE};
##  return unless $CanUseRBL && $ValidateRBL;
  ($rbls_returned,@listed_by)=();
  if (@{$this->{RBLcache}}) {
   ($rbls_returned,@listed_by)=@{$this->{RBLcache}};
  } else {
   ($skip)=();
   $ip=$this->{ip};
   unless (checkNeeded($fh,$RBLFailColl,$rblTestMode,$spamlover)) {
    mlogCond($fh,"RBL lookup skipped (unnecessary)",$RBLLog);
    $skip=1;
   } elsif (matchIP($ip,'noRBL')) {
    mlogCond($fh,"RBL lookup skipped (noRBL IP)",$RBLLog);
    $this->{myheader}.="X-Assp-Received-RBL: lookup skipped (noRBL IP); client-ip=$ip\015\012" if $AddRBLHeader;
    $skip=1;
   }
   unless ($skip) {
    $rbl=RBL->new(lists       => [@rbllist],
                  server      => $nameservers[0],
                  max_hits    => $RBLmaxhits,
                  max_replies => $RBLmaxreplies,
                  query_txt   => 0,
                  max_time    => $RBLmaxtime,
                  timeout     => 1);
    ($received_rbl)=();
    $Stats{providerQueriesRBL}++;
    $time=Time::HiRes::time() if $AvailHiRes;
    return call('L1',$rbl->lookup($fh,$ip)); L1:     
    if ($AvailHiRes) {
     $time=Time::HiRes::time()-$time;
     $Stats{providerTimeRBL}+=$time;
     $Stats{providerMinTimeRBL}=$time if $time<$Stats{providerMinTimeRBL} || !$Stats{providerMinTimeRBL};
     $Stats{providerMaxTimeRBL}=$time if $time>$Stats{providerMaxTimeRBL};
    }
    @listed_by=$rbl->listed_by();
    $rbls_returned=$#listed_by+1;
    if ($rbls_returned>=$RBLmaxhits) {
     $received_rbl="Received-RBL: fail ($myName: local policy) rbl=@listed_by; client-ip=$ip";
    } elsif ($rbls_returned>0) {
     $received_rbl="Received-RBL: neutral ($myName: local policy) rbl=@listed_by; client-ip=$ip";
    } else {
     $received_rbl="Received-RBL: pass ($myName: local policy) rbl=none; client-ip=$ip";
    }
    mlogCond($fh,$received_rbl,$RBLLog);
    $this->{myheader}.="X-Assp-$received_rbl\015\012" if $AddRBLHeader;
   }
   @{$this->{RBLcache}}=($rbls_returned,@listed_by);
  }
  if ($rbls_returned>=$RBLmaxhits) {
   $err=$RBLError;
   $err=~s/RBLNAME/@listed_by/g;
   thisIsSpam($fh,'failed RBL checks',$err,$rblTestMode,$spamlover,$RBLFailColl,'rblfails',1);
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub ipNetwork {
 my ($ip,$cidr)=@_;
 my $u32=unpack 'N', pack 'CCCC', split /\./, $ip;
 my $mask=unpack 'N', pack 'B*', '1' x $cidr . '0' x (32-$cidr);
 return join '.', unpack 'CCCC', pack 'N', $u32 & $mask;
}

sub ipBroadcast {
 my ($ip,$cidr)=@_;
 my $u32=unpack 'N', pack 'CCCC', split /\./, $ip;
 my $mask=unpack 'N', pack 'B*', '1' x $cidr . '0' x (32-$cidr);
 return join '.', unpack 'CCCC', pack 'N', $u32 | ~$mask;
}

# do Delaying checks
sub checkDelaying {
 my ($fh,$rcpt)=@_;
 my $this=$Con{$fh};
 return 1 if $this->{relayok} || $this->{mISPRE} || $this->{noprocessing};
 return 1 unless $EnableDelaying;
 my $time=$UseLocalTime ? localtime() : gmtime();
 my $tz=$UseLocalTime ? tzStr() : '+0000';
 $time=~s/... (...) +(\d+) (........) (....)/$2 $1 $4 $3/;
 if ($this->{mWLDRE}) {
  mlogCond($fh,"recipient not delayed (sender whitelisted): $rcpt",$DelayLog);
  $this->{myheader}.="X-Assp-Delay: not delayed (sender whitelisted); $time $tz\015\012" if $DelayAddHeader;
  return 1;
 }
 my $a=lc $this->{mailfrom};
 if (!$DelayWL && $Whitelist{$a}) {
  mlogCond($fh,"recipient not delayed (whitelisted): $rcpt",$DelayLog);
  $this->{myheader}.="X-Assp-Delay: not delayed (whitelisted); $time $tz\015\012" if $DelayAddHeader;
  return 1;
 }
 if (matchIP($this->{ip},'noDelay')) {
  mlogCond($fh,"recipient not delayed (noDelay IP): $rcpt",$DelayLog);
  $this->{myheader}.="X-Assp-Delay: not delayed (noDelay IP); $time $tz\015\012" if $DelayAddHeader;
  return 1;
 }
 if ($this->{allLoveNoDelaying}) {
  mlogCond($fh,"recipient not delayed (spamlover): $rcpt",$DelayLog);
  $this->{myheader}.="X-Assp-Delay: not delayed (spamlover); $time $tz\015\012" if $DelayAddHeader;
  return 1;
 }
 if ($DelayNormalizeVERPs) {
  # strip extension
  $a=~s/\+.*(?=@)//;
  # replace numbers with '#'
  $a=~s/\b\d+\b(?=.*@)/#/g;
 }
 my $ip=$DelayUseNetblocks ? ipNetwork($this->{ip},24) : $this->{ip};
 my $hash="$ip $a ". lc $rcpt;
 # get sender domain
 my $awhite=$a;
 $awhite=~s/.*@//;
 my $hashwhite="$ip $awhite";
 if ($CanUseMD5Keys) {
  $hash=Digest::MD5::md5_hex($hash);
  $hashwhite=Digest::MD5::md5_hex($hashwhite);
 }
 my $t=time;
 my $ret=0;
 if (!exists $DelayWhite{$hashwhite}) {
  if (!exists $Delay{$hash}) {
   return -1 if checkRateLimit($fh,'rcptDelayed',0,0)<0;
   mlogCond($fh,"adding new triplet: ($ip,$a,". lc $rcpt .')',$DelayLog);
   $Delay{$hash}=$t unless $this->{simulating};
   $Stats{rcptDelayed}++;
  } else {
   my $interval=$t-$Delay{$hash};
   my $intfmt=formatTimeInterval($interval,0);
   if ($interval<$DelayEmbargoTime*60) {
    return -1 if checkRateLimit($fh,'rcptEmbargoed',0,0)<0;
    mlogCond($fh,"embargoing triplet: ($ip,$a,". lc $rcpt .") waited: $intfmt",$DelayLog);
    $Stats{rcptEmbargoed}++;
   } elsif ($interval<$DelayEmbargoTime*60+$DelayWaitTime*3600) {
    mlogCond($fh,"whitelisting triplet: ($ip,$a,". lc $rcpt .") waited: $intfmt",$DelayLog);
    unless ($this->{simulating}) {
     delete $Delay{$hash};
     $DelayWhite{$hashwhite}=$t;
    }
    $this->{myheader}.="X-Assp-Delay: delayed for $intfmt; $time $tz\015\012" if $DelayAddHeader;
    $ret=1;
   } else {
    return -1 if checkRateLimit($fh,'rcptDelayedLate',0,0)<0;
    mlogCond($fh,"late triplet encountered, deleting: ($ip,$a,". lc $rcpt .") waited: $intfmt",$DelayLog);
    $Delay{$hash}=$t unless $this->{simulating};
    $Stats{rcptDelayedLate}++;
   }
  }
 } else {
  my $interval=$t-$DelayWhite{$hashwhite};
  my $intfmt=formatTimeInterval($interval,0);
  if ($interval<$DelayExpiryTime*86400) {
   mlogCond($fh,"renewing whitelisted tuplet: ($ip,$awhite) age: ". $intfmt,$DelayLog);
   unless ($this->{simulating}) {
    $DelayWhite{$hashwhite}=$t;
    # multiple rcpt's
    delete $Delay{$hash};
   }
   $this->{myheader}.="X-Assp-Delay: not delayed (auto whitelisted); $time $tz\015\012" if $DelayAddHeader;
   $ret=1;
  } else {
   return -1 if checkRateLimit($fh,'rcptDelayedExpired',0,0)<0;
   mlogCond($fh,"deleting expired tuplet: ($ip,$awhite) age: ". $intfmt,$DelayLog);
   unless ($this->{simulating}) {
    delete $DelayWhite{$hashwhite};
    $Delay{$hash}=$t;
   }
   $Stats{rcptDelayedExpired}++;
  }
 }
 unless ($ret) {
  $this->{delayed}=1;
  unless ($this->{isRelay} || $this->{isbounce}) {
   mlogCond($fh,"recipient delayed: $rcpt",$DelayLog);
   my $reply=$DelayError ? $DelayError : '451 4.7.1 Please try again later';
   sendque($fh,"$reply\015\012",1);
   doneStats($fh,0); # $stats not set deliberately
   $ret=-1; # but keep connection open
  }
 }
 return $ret;
}

# delete whitelisted tuplet
sub delayWhiteExpire {
 return unless $EnableDelaying && $DelayExpireOnSpam;
 my $fh=shift;
 my $this=$Con{$fh};
 my $a=lc $this->{mailfrom};
 # get sender domain
 $a=~s/.*@//;
 my $ip=$DelayUseNetblocks ? ipNetwork($this->{ip},24) : $this->{ip};
 my $hash="$ip $a";
 $hash=Digest::MD5::md5_hex($hash) if $CanUseMD5Keys;
 if ($DelayWhite{$hash}) {
  # delete whitelisted (IP+sender domain) tuplet
  mlogCond($fh,"deleting spamming whitelisted tuplet: ($ip,$a) age: ". formatTimeInterval(time-$DelayWhite{$hash},0),$DelayLog);
  delete $DelayWhite{$hash} unless $this->{simulating};
 }
}

sub checkLine {
 my ($fh,$l)=@_;
 my $this=$Con{$fh};
 return $this->{skipcheckLine}=1 if $this->{relayok} || $this->{mISPRE};
 return $this->{skipcheckLine}=1 unless $EnableMsgVerify;
 return $this->{skipcheckLine}=1 if $AVBytes && $this->{maillength}>=$AVBytes;
 return $this->{skipcheckLine}=1 if $this->{mNMVRE};
 return unless checkNeeded($fh,$malformedColl,$malformedTestMode,$this->{allLoveMalformedSpam});
 if ($MsgVerifyLineLength && length($l)>$MsgVerifyLineLength) {
  thisIsSpam($fh,'oversized line',$SpamError,$malformedTestMode,$this->{allLoveMalformedSpam},$malformedColl,'malformed',1);
 }
}

sub checkHeader {
 my $fh=shift;
 my $this=$Con{$fh};
 return if $this->{relayok} || $this->{mISPRE};
 return unless $EnableMsgVerify;
 return if $AVBytes && $this->{maillength}>=$AVBytes;
 return if $this->{mNMVRE};
 return unless checkNeeded($fh,$malformedColl,$malformedTestMode,$this->{allLoveMalformedSpam});
 if ($MsgVerifyHeaders && $this->{header}!~/^$HeaderAllCRLFRe+$/) {
  thisIsSpam($fh,'malformed headers',$SpamError,$malformedTestMode,$this->{allLoveMalformedSpam},$malformedColl,'malformed',1);
 }
}

# prepare ClamAV COMMAND & STREAM connections
sub prepareClamAV {
 my $fh;
 my ($this,$s,$buf,$resp,$destination,$st);
 my $sref=$Tasks{$CurTaskID}->{prepareClamAV}||=[sub{
  $fh=shift;
 },sub{&jump;
  $this=$Con{$fh};
  return unless $AvUseClamAV;
  return if !$Avlocal && $this->{mailfromlocal};
  return unless checkNeeded($fh,$viriColl);
  $s=new IO::Socket::INET(Proto=>'tcp',PeerAddr=>$AvDestination,Timeout=>2);
  unless ($s) {
   mlogCond($fh,"couldn't create command socket to $AvDestination -- aborting ClamAV scan",$AvLog);
   return;
  }
  waitTaskWrite(0,$s,10);
  return cede('L1'); L1:
  unless (getTaskWaitResult(0)) {
   mlogCond($fh,'timeout while sending command -- aborting ClamAV scan',$AvLog);
   close $s;
   return;
  }
  $buf="STREAM\n";
  unless ($s->syswrite($buf,length($buf))>0) {
   mlogCond($fh,'disconnected while sending command -- aborting ClamAV scan',$AvLog);
   close $s;
   return;
  }
  waitTaskRead(0,$s,10);
  return cede('L2'); L2:
  unless (getTaskWaitResult(0)) {
   mlogCond($fh,'timeout while waiting for command response -- aborting ClamAV scan',$AvLog);
   close $s;
   return;
  }
  unless ($s->sysread($buf,256)>0) {
   # clamd disconnected while we were waiting for input
   mlogCond($fh,'disconnected while receiving command response -- aborting ClamAV scan',$AvLog);
   close $s;
   return;
  }
  chomp($buf);
  if (($resp)=$buf=~/^PORT (\d+)/) {
   $destination=$AvDestination;
   $destination=~s/^(.*?)(?::\d+)?$/$1:$resp/;
   $st=new IO::Socket::INET(Proto=>'tcp',PeerAddr=>$destination,Timeout=>2);
   unless ($st) {
    mlogCond($fh,"couldn't create stream socket to $destination -- aborting ClamAV scan",$AvLog);
    close $s;
    return;
   }
   mlogCond($fh,"connected to ClamAV stream socket at $destination",$AvLog);
   # all connections are prepared
   $SMTPSessions{$this->{sfh}}->{clamdfh}=$s; # command fh
   $SMTPSessions{$this->{sfh}}->{clamdstfh}=$st; # stream fh
  } else {
   mlogCond($fh,"unknown command response: '$buf' -- aborting ClamAV scan",$AvLog);
   close $s;
   return;
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub checkVirus {
 my ($fh,$l);
 my ($this,$sfh,$st,$av,$r,$n,$err);
 my $sref=$Tasks{$CurTaskID}->{checkVirus}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  $this=$Con{$fh};
  return $this->{skipcheckVirus}=1 if !$Avlocal && $this->{mailfromlocal};
  return unless checkNeeded($fh,$viriColl);
  if ($AvUseClamAV) {
   # scan for viruses using ClamAV's clamd daemon
   $sfh=$this->{sfh};
   $st=$SMTPSessions{$sfh}->{clamdstfh};
   return unless $st;
   waitTaskWrite(0,$st,10);
   return cede('L1'); L1:
   unless (getTaskWaitResult(0)) {
    mlogCond($fh,'timeout while sending stream to ClamAV ('.needEs($this->{maillength},' byte','s').')',$AvLog);
    doneClamAV($fh,2); # close STREAM
    return;
   }
   unless ($st->syswrite($l,length($l))>0) {
    # clamd disconnected while we were streaming (StreamMaxLength is in effect?)
    mlogCond($fh,'disconnected while sending stream to ClamAV ('.needEs($this->{maillength},' byte','s').')',$AvLog);
    doneClamAV($fh,2); # close STREAM
    return;
   }
  } else {
   # scan for viruses using our AV engine
   return $this->{skipcheckVirus}=1 unless $AvDbs;
   return $this->{skipcheckVirus}=1 if $AVBytes && $this->{maillength}>=$AVBytes;
   ($av)=();
   unless ($av=$Con{$fh}->{av}) {
    $av=$Con{$fh}->{av}=Av->new();
   }
   $l=~s/([a-zA-Z0-9+\/=]{40,}\s*)/base64decode($1)/e;
   ($r)=();
   $n=0;
   for(;$n<length($l);$n++) {
    if ($r=$av->addchar(substr($l,$n,1))) {
     # this mail is infected
     $err=$AvError;
     $err=~s/\$infection/$r->[1]/gi;
     thisIsSpam($fh,"virus detected '$r->[1]'",$err,0,0,$viriColl,'viridetected',1);
    }
   }
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

# check result response from ClamAV
sub checkClamAV {
 my $fh;
 my ($this,$sfh,$s,$buf,$resp,$code,$virus,$er);
 my $sref=$Tasks{$CurTaskID}->{checkClamAV}||=[sub{
  $fh=shift;
 },sub{&jump;
  $this=$Con{$fh};
  return unless $AvUseClamAV;
  return if !$Avlocal && $this->{mailfromlocal};
  return unless checkNeeded($fh,$viriColl);
  doneClamAV($fh,2); # close STREAM
  $sfh=$this->{sfh};
  $s=$SMTPSessions{$sfh}->{clamdfh};
  return unless $s;
  waitTaskRead(0,$s,$Avmaxtime);
  return cede('L1'); L1:
  unless (getTaskWaitResult(0)) {
   mlogCond($fh,'timeout while waiting for result response from ClamAV',$AvLog);
  } elsif ($s->sysread($buf,256)>0) {
   chomp($buf);
   if (($resp,$code)=$buf=~/^(.*)\s+(ERROR|FOUND|OK)$/) {
    if ($code eq 'ERROR') {
     mlogCond($fh,"error result response from ClamAV: '$resp'",$AvLog);
    } elsif ($code eq 'FOUND') {
     # this mail is infected
     ($virus)=$resp=~/\s+(.*)/;
     $er=$AvError;
     $er=~s/\$infection/$virus/gi;
     thisIsSpam($fh,"virus detected '$virus'",$er,0,0,$viriColl,'viridetected',1);
    } else {
     # file OK
    }
   } else {
    mlogCond($fh,"unknown result response from ClamAV: '$buf'",$AvLog);
   }
  } else {
   # clamd disconnected while we were waiting for input
   mlogCond($fh,'disconnected while receiving result response from ClamAV',$AvLog);
  }
  doneClamAV($fh,1); # close COMMAND
 }];
 &{$sref->[0]};
 return $sref->[1];
}

# close COMMAND, STREAM or both ClamAV connections
# param = 2 bits flag specifying connections to be closed
sub doneClamAV {
 my ($fh,$param)=@_;
 my $this=$Con{$fh};
 my $sfh=$this->{sfh};
 if (($param & 1) && $SMTPSessions{$sfh}->{clamdfh}) {
  mlogCond($fh,'closing command connection to ClamAV',$AvLog);
  close $SMTPSessions{$sfh}->{clamdfh};
  delete $SMTPSessions{$sfh}->{clamdfh};
 }
 if (($param & 2) && $SMTPSessions{$sfh}->{clamdstfh}) {
  mlogCond($fh,'closing stream connection to ClamAV',$AvLog);
  close $SMTPSessions{$sfh}->{clamdstfh};
  delete $SMTPSessions{$sfh}->{clamdstfh};
 }
}

sub checkBomb {
 my $fh=shift;
 my $this=$Con{$fh};
 return unless $bombRe;
 return if $this->{mNBSRE};
 return unless checkNeeded($fh,$spamBombColl,0,$this->{allLoveBombsSpam});
 if ($this->{header}=~$bombReRE) {
  mlogCond($fh,"header matches bombRe: '$^R'",$RELog);
  thisIsSpam($fh,'mail bomb',$bombError,0,$this->{allLoveBombsSpam},$spamBombColl,'bombs',1);
 } elsif ($this->{body}=~$bombReRE) {
  mlogCond($fh,"body matches bombRe: '$^R'",$RELog);
  thisIsSpam($fh,'mail bomb',$bombError,0,$this->{allLoveBombsSpam},$spamBombColl,'bombs',1);
 }
}

sub checkScript {
 my $fh=shift;
 my $this=$Con{$fh};
 return unless $scriptRe;
 return if $this->{mNBSRE};
 return unless checkNeeded($fh,$scriptColl,0,$this->{allLoveBombsSpam});
 if ($this->{header}=~$scriptReRE) {
  mlogCond($fh,"header matches scriptRe: '$^R'",$RELog);
  thisIsSpam($fh,'contains scripting',$scriptError,0,$this->{allLoveBombsSpam},$scriptColl,'scripts',1);
 } elsif ($this->{body}=~$scriptReRE) {
  mlogCond($fh,"body matches scriptRe: '$^R'",$RELog);
  thisIsSpam($fh,'contains scripting',$scriptError,0,$this->{allLoveBombsSpam},$scriptColl,'scripts',1);
 }
}

sub checkAttach {
 my ($fh,$reason,$block,$coll)=@_;
 my $this=$Con{$fh};
 $this->{checkedattach}='attachments unchecked';
 return unless $block;
 return unless checkNeeded($fh,$coll);
 return if matchSL($this->{mailfrom},'noAttachment');
 while ($this->{body}=~/^Content-(?:$HeaderNameSepRe)($HeaderValueRe)name\s*=\s*($HeaderValueRe)/gimo) {
  # skip forwarded messages whose subject ends with a .com domain eg
  next if $1=~/message\/rfc822/im;
  my $s=decodeMimeWords($2);
  if ($s=~$badattachRE[$block]) {
   # clean and unquote
   my $name=$1; $name=~tr/\r\n\t/ /; $name=~s/^[\'\"](.*)[\'\"]$/$1/;
   mlogCond($fh,"matches badattachRe: '$name'",$RELog);
   thisIsSpam($fh,"bad attachment $reason",$AttachmentError,0,0,$coll,'viri',1);
   return;
  }
 }
 $this->{checkedattach}='no bad attachments';
}

# do URIBL checks
sub checkURIBL {
 my $fh;
 my ($this,%domains,$ucnt,$dcnt,$uri,$orig_uri,$i,$ip,$uribl,$received_uribl,$uribl_result);
 my (@listed_by,$listed_domain,$uribls_returned,@domains,$n,$lcnt,$err);
 my $sref=$Tasks{$CurTaskID}->{checkURIBL}||=[sub{
  $fh=shift;
 },sub{&jump;
  $this=$Con{$fh};
  return if $this->{relayok} || $this->{mISPRE};
##  return unless $CanUseURIBL && $ValidateURIBL;
  unless (checkNeeded($fh,$URIBLFailColl,$uriblTestMode,$this->{allLoveURIBLSpam})) {
   mlogCond($fh,"URIBL lookup skipped (unnecessary)",$RBLLog);
   return;
  } elsif (matchSL($this->{mailfrom},'noURIBL')) {
   mlogCond($fh,"URIBL lookup skipped (noURIBL sender)",$RBLLog);
   $this->{myheader}.="X-Assp-Received-RBL: lookup skipped (noURIBL sender)" if $AddURIBLHeader;
   return;
  }
  (%domains,$ucnt,$dcnt)=();
  while ($this->{body}=~/(?:https?|ftp)[\041-\176]{0,3}\:\/{1,3}($URICharRe+)|((?:www|ftp)\.$URICharRe+)/gi) {
   $uri=$1 || $2;
   # RFC 2821, section 4.5.2, 'Transparency': delete leading period char
   $uri=~s/\=(?:\015?\012|\015)\.?//g;
   $uri=~s/[=%]([0-9a-f]{2})/chr(hex($1))/gie;
   $uri=~s/&#(\d{1,3});?/chr($1)/ge;
   $uri=~tr/;//d;
   if ($uri=~/(?:[^\s\/\@]+\@)?([0-9a-z\-\_\.]+)/i) {
    $orig_uri=$uri=$1;
    $uri=~s/\.{2,}/\./g;
    $uri=~s/^\.//;
    $uri=~s/\.$//;
    if ($uri=~/^$IPQuadRE$/io) {
     ($i,$ip)=();
     while ($i<10) { $ip=($ip<<8)+oct(${++$i})+hex(${++$i})+${++$i}; }
     $uri=inet_ntoa(pack('N',$ip));
     if ($URIBLNoObfuscated && $orig_uri!~/^\Q$uri\E/i) {
      $this->{myheader}.="X-Assp-Received-URIBL: fail ($myName: local policy) contains obfuscated uri\015\012" if $AddURIBLHeader;
      thisIsSpam($fh,'failed URIBL checks (obfuscated uri)',$URIBLPolicyError,$uriblTestMode,$this->{allLoveURIBLSpam},$URIBLFailColl,'uriblfails',1);
      return;
     }
    } else {
     if ($URIBLNoObfuscated && $orig_uri!~/^\Q$uri\E/i) {
      $this->{myheader}.="X-Assp-Received-URIBL: fail ($myName: local policy) contains obfuscated uri\015\012" if $AddURIBLHeader;
      thisIsSpam($fh,'failed URIBL checks (obfuscated uri)',$URIBLPolicyError,$uriblTestMode,$this->{allLoveURIBLSpam},$URIBLFailColl,'uriblfails',1);
      return;
     }
     if ($uri=~$URIBLCCTLDSRE || $uri=~/([^\.]+\.[^\.]+)$/) {
      $uri=$1;
     } else {
      next;
     }
    }
    next if $uri=~$URIBLWLDRE;
    if ($URIBLmaxuris && ++$ucnt>$URIBLmaxuris) {
     $this->{myheader}.="X-Assp-Received-URIBL: fail ($myName: local policy) maximum uris exceeded\015\012" if $AddURIBLHeader;
     thisIsSpam($fh,'failed URIBL checks (maximum uris exceeded)',$URIBLPolicyError,$uriblTestMode,$this->{allLoveURIBLSpam},$URIBLFailColl,'uriblfails',1);
     return;
    }
    $dcnt++ unless $domains{lc $uri}++;
    if ($URIBLmaxdomains && $dcnt>$URIBLmaxdomains) {
     $this->{myheader}.="X-Assp-Received-URIBL: fail ($myName: local policy) maximum unique domain uris exceeded\015\012" if $AddURIBLHeader;
     thisIsSpam($fh,'failed URIBL checks (maximum unique domain uris exceeded)',$URIBLPolicyError,$uriblTestMode,$this->{allLoveURIBLSpam},$URIBLFailColl,'uriblfails',1);
     return;
    }
   }
  }
  $uribl=RBL->new(lists       => [@uribllist],
                  server      => $nameservers[0],
                  max_hits    => $URIBLmaxhits,
                  max_replies => $URIBLmaxreplies,
                  query_txt   => 0,
                  max_time    => $URIBLmaxtime,
                  timeout     => 1);
  ($received_uribl,$uribl_result,@listed_by,$listed_domain,$uribls_returned)=();
  @domains=keys %domains;
  for ($n=0;$n<@domains;$n++) {
   $domain=$domains[$n];
   $Stats{providerQueriesURIBL}++;
   $time=Time::HiRes::time() if $AvailHiRes;
   return call('L1',$uribl->lookup($fh,$domain)); L1:
   if ($AvailHiRes) {
    $time=Time::HiRes::time()-$time;
    $Stats{providerTimeURIBL}+=$time;
    $Stats{providerMinTimeURIBL}=$time if $time<$Stats{providerMinTimeURIBL} || !$Stats{providerMinTimeURIBL};
    $Stats{providerMaxTimeURIBL}=$time if $time>$Stats{providerMaxTimeURIBL};
   }
   @listed_by=$uribl->listed_by();
   $lcnt=$#listed_by+1;
   $uribls_returned=$lcnt if $lcnt>$uribls_returned;
   if ($uribls_returned>=$URIBLmaxhits) {
    $listed_domain=$domain;
    last;
   }
  }
  if ($uribls_returned>=$URIBLmaxhits) {
   $received_uribl="Received-URIBL: fail ($myName: local policy) uribl=@listed_by; domain=$listed_domain";
  } elsif ($uribls_returned>0) {
   $received_uribl="Received-URIBL: neutral ($myName: local policy) uribl=some";
  } else {
   $received_uribl="Received-URIBL: pass ($myName: local policy) uribl=none";
  }
  mlogCond($fh,$received_uribl,$RBLLog);
  $this->{myheader}.="X-Assp-$received_uribl\015\012" if $AddURIBLHeader;
  if ($uribls_returned>=$URIBLmaxhits) {
   $err=$URIBLError;
   $err=~s/URIBLNAME/@listed_by/g;
   thisIsSpam($fh,'failed URIBL checks',$err,$uriblTestMode,$this->{allLoveURIBLSpam},$URIBLFailColl,'uriblfails',1);
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub checkMaxErrors {
 my ($fh,$stats,$expire,$relayok)=@_;
 my $this=$Con{$fh};
 $Stats{$stats}++ if $stats;
 # increment error and drop line if necessary
 if (++($this->{serverErrors})>$MaxErrors) {
  delayWhiteExpire($fh) if $expire;
  return -1 if checkRateLimit($fh,'msgMaxErrors',$relayok,0)<0;
  my $err="max errors ($MaxErrors) exceeded -- dropping connection";
  mlogCond($fh,$err,1);
  sendError($fh,"($err)",1,'msgMaxErrors');
  return -1;
 }
 return 1;
}

# RateLimit hash description:
# key:
#  client_ip
# value:
#  added_date \004 blocked_date_delta \004 block_reason_event_id \003 event_record1 event_record2 ...
# event_record:
#  added_date_delta \004 event_id \003
sub checkRateLimit {
 my ($fh,$name,$relayok,$spamlover)=@_;
 my $this=$Con{$fh};
 return 1 if $relayok && $this->{relayok} || $this->{mISPRE} || $this->{isRelay};
 return 1 unless $EnableRateLimit;
 return 1 unless RLIBTEventEnabled($name);
 return 1 if $spamlover && $this->{allLoveRateLimitSpam};
 return 1 if $this->{mNRLRE};
 my $event=$ConfigRateLimitEvents{$name};
 my $id=$event->{id};
 my $limit=$event->{limit};
 my $interval=$event->{interval};
 my $t=time;
 my $added=$t;
 my ($blocked,$reason)=(-1)x2;
 my $ip=$RateLimitUseNetblocks ? ipNetwork($this->{ip},24) : $this->{ip};
 unless ($this->{simulating}) {
  $RateLimit{$ip}="$added\004$blocked\004$reason\003" unless exists $RateLimit{$ip};
 }
 if ($limit>0 && $interval>0) {
  my @a=split("\003",$RateLimit{$ip});
  ($added,$blocked,$reason)=split("\004",shift @a);
  my $since=$t-$added-$interval;
  my $rec_cnt=0;
  foreach my $s (@a) {
   # count qualifying records
   my ($rec_added,$rec_id)=split("\004",$s);
   $rec_cnt++ if $rec_id==$id && $rec_added>$since;
  }
  if ($rec_cnt>=$limit) {
   # rate limit exceeded
   my $block=$event->{block};
   unless ($this->{simulating}) {
    $RateLimit{$ip}="$added\004";
    $RateLimit{$ip}.=($block>0 ? $t-$added : -1)."\004";
    $RateLimit{$ip}.=($block>0 ? $id : -1)."\003";
    $RateLimit{$ip}.=join("\003",@a)."\003" if @a;
   }
   my $err="rate limit ($limit/".formatTimeInterval($interval,0).") exceeded; reason=$name";
   $err.=', blocking client for '.formatTimeInterval($block,0) if $block>0;
   mlogCond($fh,$err,$RateLimitLog);
   slog($fh,"($err)",1,'I');
   sendError($fh,$block>0 ? $RateLimitBlockedError : $RateLimitError,0,'msgRateLimited');
   return -1;
  }
 }
 $RateLimit{$ip}.=($t-$added)."\004$id\003" unless $this->{simulating};
 return 1;
}

# RateLimit Block checks
sub checkRateLimitBlock {
 my ($fh,$spamlover)=@_;
 my $this=$Con{$fh};
 return 1 if $this->{relayok} || $this->{mISPRE};
## return 1 unless $EnableRateLimit;
 return 1 if $this->{mNRLRE};
 my $ip=$this->{ip};
 my $port=$this->{port};
 # also check for entries, when $RateLimitUseNetblocks was enabled
 my $recs=$RateLimit{$ip} || $RateLimit{ipNetwork($ip,24)};
 my @a=split("\003",$recs);
 my ($added,$blocked,$reason)=split("\004",shift @a);
 if ($blocked>=0 && $reason>=0) {
  my $event=$ConfigRateLimitEvents{$reason};
  my $expires=$added+$blocked+$event->{block}-time;
  if ($expires>0) {
   my $name=$event->{name};
   my $text="blocked by RateLimit; reason=$name expires=".formatTimeInterval($expires,0);
   if ($spamlover && $this->{allLoveRateLimitSpam}) {
    mlogCond($fh,"passing because spamlover(s): $this->{rcpt}, otherwise $text",$RateLimitLog && !$this->{mNLOGRE}) if $this->{indata};
   } else {
    mlogCond($fh,"$text",$RateLimitLog && !$this->{mNLOGRE});
    slog($fh,"($text)",1,'I');
    sendError($fh,$RateLimitBlockedError);
    $Stats{smtpConnRateLimit}++;
    return -1;
   }
  }
 }
 return 1;
}

#####################################################################################
#                Bayesian SPAM Detection

# check if the message is spam, based on Bayesian factors in $Spamdb
sub checkSpam {
 my $fh=shift;
 my $this=$Con{$fh};
 return unless checkNeeded($fh,$baysSpamColl,$baysTestMode,$this->{allLoveBaysSpam});
 if ($whiteRe) {
  if ($this->{header}=~$whiteReRE) {
   mlogCond($fh,"header matches whiteRe: '$^R'",$RELog);
   return;
  } elsif ($this->{body}=~$whiteReRE) {
   mlogCond($fh,"body matches whiteRe: '$^R'",$RELog);
   return;
  }
 }
 if ($blackRe) {
  if ($this->{header}=~$blackReRE) {
   mlogCond($fh,"header matches blackRe: '$^R'",$RELog);
   thisIsSpam($fh,'Bayesian spam (header matches blackRe)',$SpamError,$baysTestMode,$this->{allLoveBaysSpam},$baysSpamColl,'bspams',1);
   return;
  } elsif ($this->{body}=~$blackReRE) {
   mlogCond($fh,"body matches blackRe: '$^R'",$RELog);
   thisIsSpam($fh,'Bayesian spam (body matches blackRe)',$SpamError,$baysTestMode,$this->{allLoveBaysSpam},$baysSpamColl,'bspams',1);
   return;
  }
 }
 my $mail=clean($this->{header}."\015\012".$this->{body});
 if ($mail=~$whiteReRE) {
  mlogCond($fh,"matches whiteRe: '$^R'",$RELog);
  return;
 }
 if ($mail=~$blackReRE) {
  mlogCond($fh,"matches blackRe: '$^R'",$RELog);
  thisIsSpam($fh,'Bayesian spam (matches blackRe)',$SpamError,$baysTestMode,$this->{allLoveBaysSpam},$baysSpamColl,'bspams',1);
  return;
 }
 if ($WhitelistOnly) {
  thisIsSpam($fh,'Bayesian spam (WhitelistOnly)',$SpamError,$baysTestMode,$this->{allLoveBaysSpam},$baysSpamColl,'bspams',1);
  return;
 }
 my $ip=$this->{ip};
 my ($ip3)=$ip=~/(.*)\.\d+$/;
 my ($v,$lt,$t,$nt,%seen,%got);
 my @t;
 if (defined($Dnsbl{$ip}) || defined($Dnsbl{$ip3})) {
  mlogCond($fh,"$ip dnsbl hit",1);
  addSpamAnalysis($fh,"$ip dnsbl hit (adds 0.97 0.97)");
  push(@t,0.97,0.97);
 }
 if ($greylist) {
  if ($this->{mISPRE}) {
   if ($ispgreyvalue) {
    $v=$ispgreyvalue;
   } else {
    $v=$Greylist{x};
   }
  } else {
   $v=$Greylist{$ip3} || $Greylist{x};
  }
  if ($v) {
   addSpamAnalysis($fh,"$ip has a greylist value of $v (adds $v $v)");
   push(@t,$v,$v);
  }
 }
 while ($mail=~/([-\$A-Za-z0-9\'\.!\240-\377]+)/g) {
  next if length($1)>20 || length($1)<2;
  $nt=lc $1; $nt=~s/[,.']+$//; $nt=~s/!!!+/!!/g; $nt=~s/--+/-/g;
  next unless $nt;
  $lt=$t; $t=$nt;
  next unless length($lt)>1 || ($lt && length($t)>1);
  my $j="$lt $t";
  next if $seen{$j}++>1; # first two occurances are significant
  push(@t,$v) if $v=$Spamdb{$j}; $got{$j}=$v if $v;
 }
 my $cnt=0;
 my $g;
 foreach (sort {abs($got{$b}-.5)<=>abs($got{$a}-.5)} keys %got) {
  $g=sprintf("%f",$got{$_});
  addSpamAnalysis($fh,"\"$_\" $g");
  last if (($cnt++)>30);
 }
 @t=sort {abs($b-.5)<=>abs($a-.5)} @t;
 @t=@t[0..30];
 $g='Analysis totals:';
 foreach (@t) {$g.=sprintf (" %f",$_) if $_;}
 addSpamAnalysis($fh,"$g");
 my $p1=1; my $p2=1; foreach my $p (@t) {if ($p) {$p1*=$p; $p2*=(1-$p);}}
 $p1=$p1/($p1+$p2);
 addSpamAnalysis($fh,sprintf("Bayesian probability: %f",$p1));
 if ($p1<0.6) {
  $this->{spamprob}=$p1 unless $this->{spamfound};
 } else {
  thisIsSpam($fh,'Bayesian spam',$SpamError,$baysTestMode,$this->{allLoveBaysSpam},$baysSpamColl,'bspams',$p1);
 }
}

sub addSpamAnalysis {
 my ($fh,$probs)=@_;
 return unless $AddSpamAnalysisHeader;
 # mask non printable characters with '?'
 $probs=~tr/\011\012\015\040-\176/?/c;
 my $this=$Con{$fh};
 if ($this->{myheader}=~/^X-Assp-Spam-Analysis$HeaderSepRe/imo) {
  $this->{myheader}=~s/^(X-Assp-Spam-Analysis$HeaderSepValueRe)/$1, $probs/gimo;
 } else {
  $this->{myheader}.="X-Assp-Spam-Analysis: $probs\015\012";
 }
}

#####################################################################################
#                collectMail functions

# find an appropriate name for a collection file
sub getNewCollFileName {
 my $maillog=shift;
 my $fn;
 my $tries=3;
 if ($FilesDistribution<1.0) {
  my $p1=1.0-$FilesDistribution;
  my $p2=log($FilesDistribution);
  for (my $i=0;$i<$tries;$i++) {
   $fn=int($MaxFiles*log(1.0-rand($p1))/$p2);
   last unless -s "$base/$maillog/$fn$maillogExt";
  }
 } else {
  for (my $i=0;$i<$tries;$i++) {
   $fn=int($MaxFiles*rand());
   last unless -s "$base/$maillog/$fn$maillogExt";
  }
 }
 return $fn;
}

sub collectMail {
 my $fh=shift;
 my $this=$Con{$fh};
 # 1 = notspam folder, 2 = notspam folder & CC, 3 = mailok folder, 4 = mailok folder & CC, 5 = discard, 6 = discard & CC
 # 7 = spam folder, 8 = spam folder & CC, 9 = discard, 10 = discard & CC, 11 = virii folder, 12 = virii folder & CC
 my @dirs=('',$notspamlog,$notspamlog,$incomingOkMail,$incomingOkMail,'','',$spamlog,$spamlog,'','',$viruslog,$viruslog);
 my $maillog=$dirs[$this->{coll}];
 return unless $maillog;
 my $fn=getNewCollFileName($maillog);
 $fn="$maillog/$fn$maillogExt";
 if (open(F,">$base/$fn")) {
  binmode(F);
  print F $this->{header};
  # wrap long header lines
  headerWrap($this->{myheader});
  # sort & merge our header
  foreach my $h (@MyHeaders) {
   print F $1 if $this->{myheader}=~/^(X-Assp-\Q$h\E$HeaderSepValueCRLFRe)/m;
  }
  print F "\015\012$this->{body}";
  close F;
  # update Corpus cache
  my $det=corpusDetails($fn,1);
  my $sf=$this->{spamfound};
  my $flags=$det->[4];
  $flags|=4 if $sf; # set 'is-spam' bit
  $flags|=8 unless $sf & 4; # set 'passed-message' bit
  corpusSetFlags($fn,$flags,0);
 } else {
  mlog($fh,"error opening maillog '$base/$fn': $!");
 }
}

#####################################################################################
#                forwardSpam functions

sub forwardSpam {
 my $fh=shift;
 my $coll=$Con{$fh}->{coll};
 return unless $coll==2 || $coll==4 || $coll==6 || $coll==8 || $coll==10 || $coll==12;
 my $sf=$Con{$fh}->{spamfound};
 my $to=($sf & 4) ? $ccBlocked : $sf ? $ccSpam : $ccHam;
 return unless $to;
 if ($ccFilter && !matchSL($Con{$fh}->{mailfrom},'ccFilter')) {
  my $c;
  foreach my $a (split(' ',$Con{$fh}->{rcpt})) { $c++ if matchSL($a,'ccFilter'); }
  return unless $c;
 }
 my $s=new IO::Socket::INET(Proto=>'tcp',PeerAddr=>$smtpDestination,Timeout=>2);
 unless ($s) {
  mlog(0,"couldn't create server socket to $smtpDestination -- aborting CC connection");
  return;
 }
 addfh($s,\&FShelo);
 my $this=$Con{$s};
 $this->{isServer}=1;
 # add SMTP session
 addSession($s);
 # set session fh (sfh)
 $this->{sfh}=$s;
 slog($s,"(connected $smtpDestination)",1,'I');
 $this->{from}=$Con{$fh}->{mailfrom};
 $this->{to}=$to;
 $this->{header}=$Con{$fh}->{header};
 # clear out notification headers (MDN's)
 $this->{header}=~s/^Disposition-Notification-$HeaderAllCRLFRe//gimo; # -To & -Options
 $this->{header}=~s/^Return-Receipt-To$HeaderSepValueCRLFRe//gimo;
 # first remove the spamSubject from Subject: if it was added by us
 $this->{header}=~s/^Subject$HeaderSepRe$spamSubjectTagRE /Subject: /gim  if $sf && $spamSubject;
 # add ccBlockedSubject, ccSpamSubject or ccHamSubject to Subject:
 my $sub=($sf & 4) ? $ccBlockedSubject : $sf ? $ccSpamSubject : $ccHamSubject;
 $sub=~s/TAG/$SubjectTags{$Con{$fh}->{tag}}/g;
 if ($sub && $this->{header}!~/^Subject$HeaderSepRe\Q$sub\E /im) {
  $this->{header}=~s/^Subject$HeaderSepRe/Subject: $sub /gimo; # rewrite all Subject: headers
 }
 # add X-Intended-For: header
 $this->{header}.="X-Intended-For: $Con{$fh}->{rcpt}\015\012";
 $this->{body}=$Con{$fh}->{body};
 # chop off final 'crlf dot crlf' sequence
 # it may have been damaged by MaxBytes boundary
 $this->{body}=~s/\015\012\.(?:\015\012)?$//;
}

sub FShelo {
 my ($fh,$l);
 my $sref=$Tasks{$CurTaskID}->{FShelo}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  slog($fh,$l,0);
  if ($l=~/^ *5/) {
   FSabort($fh,"helo Expected 220, got: $l");
  } elsif ($l=~/^ *220 /) {
   $Con{$fh}->{getline}=\&FSfrom;
   sendque($fh,"HELO $myName\015\012",1);
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub FSfrom {
 my ($fh,$l);
 my $sref=$Tasks{$CurTaskID}->{FSfrom}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  slog($fh,$l,0);
  if ($l=~/^ *5/) {
   FSabort($fh,"from Expected 250, got: $l");
  } elsif ($l=~/^ *250 /) {
   $Con{$fh}->{getline}=\&FSrcpt;
   sendque($fh,"MAIL FROM:<$Con{$fh}->{from}>\015\012",1);
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub FSrcpt {
 my ($fh,$l);
 my $sref=$Tasks{$CurTaskID}->{FSrcpt}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  slog($fh,$l,0);
  if ($l=~/^ *5/) {
   FSabort($fh,"rcpt Expected 250, got: $l");
  } elsif ($l=~/^ *250 /) {
   $Con{$fh}->{getline}=\&FSdata;
   sendque($fh,"RCPT TO:<$Con{$fh}->{to}>\015\012",1);
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub FSdata {
 my ($fh,$l);
 my $sref=$Tasks{$CurTaskID}->{FSdata}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  slog($fh,$l,0);
  if ($l=~/^ *5/) {
   FSabort($fh,"data Expected 250, got: $l");
  } elsif ($l=~/^ *250 /) {
   $Con{$fh}->{getline}=\&FSdata2;
   sendque($fh,"DATA\015\012",1);
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub FSdata2 {
 my ($fh,$l);
 my ($this,$s);
 my $sref=$Tasks{$CurTaskID}->{FSdata2}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  slog($fh,$l,0);
  if ($l=~/^ *5/) {
   FSabort($fh,"data2 Expected 354, got: $l");
  } elsif ($l=~/^ *354 /) {
   $this=$Con{$fh};
   $this->{getline}=\&FSdone;
   # 'crlf dot crlf' sequence was chopped off ealier
   $s="$this->{header}\015\012".
      "$this->{body}\015\012.\015\012";
   sendque($fh,$s);
   slog($fh,'('.needEs(length($s),' byte','s').' sent)',1,'I');
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub FSdone {
 my ($fh,$l);
 my $this;
 my $sref=$Tasks{$CurTaskID}->{RMdone}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  slog($fh,$l,0);
  $this=$Con{$fh};
  $this->{indata}=0;
  if ($l=~/^ *5/) {
   FSabort($fh,"done Expected 250, got: $l");
  } elsif ($l=~/^ *250 /) {
   doneStats($fh,1,'cc');
   $this->{getline}=\&FSquit;
   sendque($fh,"QUIT\015\012",1);
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub FSabort {
 my ($fh,$l)=@_;
 mlog(0,"FSabort: $l");
 doneStats($fh,0,'cc');
 $this->{getline}=\&FSquit;
 sendque($fh,"QUIT\015\012",1);
}

sub FSquit {
 my ($fh,$l);
 my $sref=$Tasks{$CurTaskID}->{FSquit}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  slog($fh,$l,0);
  doneStats($fh,1);
  doneSession($fh,1);
 }];
 &{$sref->[0]};
 return $sref->[1];
}

#####################################################################################
#                Email Interface

# this mail isn't really a mail -- it's a spam/ham report
sub spamReport {
 my ($fh,$l);
 my ($this,$report);
 my $sref=$Tasks{$CurTaskID}->{spamReport}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  $this=$Con{$fh};
  slog($fh,$l,0);
  if ($l=~/^ *(?:DATA|BDAT (\d+))/i) {
   if ($1) {
    $this->{bdata}=$1;
   } else {
    delete $this->{bdata};
   }
   $this->{indata}=1;
   $this->{getline}=\&spamReportBody;
   $report=($this->{reporttype}==0) ? 'spam' : 'ham';
   sendque($fh,"354 OK Send $report body\015\012",1);
   return;
  } elsif ($l=~/^ *RSET/i) {
   stateReset($fh);
   sendque($this->{friend},"RSET\015\012",1);
   return;
  } elsif ($l=~/^ *QUIT/i) {
   stateReset($fh);
   sendque($this->{friend},"QUIT\015\012",1);
   return;
  } elsif ($l=~/^ *XEXCH50 +(\d+)/i) {
   sendque($fh,"504 Need to authenticate first\015\012",1);
   return;
  }
  sendque($fh,"250 OK\015\012",1);
 }];
 &{$sref->[0]};
 return $sref->[1];
}

# we're getting the body of a spam/ham report
sub spamReportBody {
 my ($fh,$l);
 my ($this,$sub);
 my $sref=$Tasks{$CurTaskID}->{spamReportBody}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  $this=$Con{$fh};
  $this->{body}.=$l;
  $this->{maillength}+=length($l);
  if ($l=~/^\.(?:\015\012)?$/ || defined($this->{bdata}) && $this->{bdata}<=0) {
   # we're done -- write the file & clean up
   slog($fh,'('.needEs($this->{maillength},' byte','s').' received)',0,'I');
   $sub=spamReportExec($fh);
   ReturnMail($fh," $sub") unless $NoHaikuCorrection;
   doneStats($fh,1,'reports');
   stateReset($fh);
   sendque($this->{friend},"RSET\015\012",1);
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub spamReportExec {
 my $fh=shift;
 my $this=$Con{$fh};
 my ($sub)=$this->{body}=~/^Subject$HeaderSepRe($HeaderValueRe)/imo;
 $sub=decodeMimeWords($sub);
 # strip report message headers
 $this->{body}=~s/^$HeaderAllCRLFRe*$HeaderCRLFRe//o;
 if ($this->{body}=~/^Received$HeaderSepValueCRLFRe/imo) { # report contains attached message
  # use subject of attached message
  ($sub)=$this->{body}=~/^Subject$HeaderSepRe($HeaderValueRe)/imo;
  $this->{body}=~s/^.*?(Received$HeaderSepValueCRLFRe)/$1/iso;
  # clear out some headers
  $this->{body}=~s/^X-Assp-$HeaderAllCRLFRe//gimo;
  $this->{body}=~s/^X-Intended-For$HeaderSepValueCRLFRe//gimo;
 } else { # report contains quoted message
  # remove 'forwarded' mark (Fw:) from subject
  $sub=~s/Fw: *(.*)/$1/is;
  my $ah; # artificial header
  $ah="From: <$1>\015\012" if $this->{body}=~/^.*?($EmailAdrRe\@$EmailDomainRe)/so;
  $ah.="Subject: $sub\015\012" if $sub;
  $this->{body}=~s/^.*?$HeaderCRLFRe((\w[^\015\012]*$HeaderCRLFRe)*Subject:)/$1/is;
  $this->{body}=~s/^[>|:] *//gm; # strip quotation marks
  $this->{body}="$ah\015\012".$this->{body} if $ah;
 }
 # remove the spamSubject from Subject: if present
 $this->{body}=~s/^Subject$HeaderSepRe$spamSubjectTagRE /Subject: /gim  if $spamSubject;
 # remove the ccHamSubject from Subject: if present
 $this->{body}=~s/^Subject$HeaderSepRe$ccHamSubjectTagRE /Subject: /gim  if $ccHamSubject;
 # remove the ccSpamSubject from Subject: if present
 $this->{body}=~s/^Subject$HeaderSepRe$ccSpamSubjectTagRE /Subject: /gim  if $ccSpamSubject;
 # remove the ccBlockedSubject from Subject: if present
 $this->{body}=~s/^Subject$HeaderSepRe$ccBlockedSubjectTagRE /Subject: /gim  if $ccBlockedSubject;
 my $maillog=($this->{reporttype}==0) ? $correctedspam : $correctednotspam;
 my $fn;
 do {
  $fn=int(100000000*rand());
  $fn="$maillog/$fn$maillogExt";
 } while (-e "$base/$fn");
 open(F,">$base/$fn");
 binmode(F);
 print F $this->{body};
 close F;
 # update Corpus cache
 corpusDetails($fn,1);
 return $sub;
}

# we're receiving an email to manipulate addresses in the whitelist/redlist
sub listReport {
 my ($fh,$l)=@_;
 my $this=$Con{$fh};
 slog($fh,$l,0);
 if ($l=~/^ *(?:DATA|BDAT (\d+))/i) {
  if ($1) {
   $this->{bdata}=$1;
  } else {
   delete $this->{bdata};
  }
  $this->{indata}=1;
  $this->{getline}=\&listReportBody;
  my $list=(($this->{reporttype} & 4)==0) ? 'whitelist' : 'redlist';
  sendque($fh,"354 OK Send $list body\015\012",1);
  return;
 } elsif ($l=~/^ *RSET/i) {
  stateReset($fh);
  sendque($this->{friend},"RSET\015\012",1);
  return;
 } elsif ($l=~/^ *QUIT/i) {
  stateReset($fh);
  sendque($this->{friend},"QUIT\015\012",1);
  return;
 } elsif ($l=~/^ *XEXCH50 +(\d+)/i) {
  sendque($fh,"504 Need to authenticate first\015\012",1);
  return;
 } else {
  # more recipients ?
  while ($l=~/($EmailAdrRe\@$EmailDomainRe)/go) {
   listReportExec($fh,$1);
   $this->{rcpt}.="$1 ";
  }
 }
 sendque($fh,"250 OK\015\012",1);
}

# we're getting the body of a whitelist/redlist report
sub listReportBody {
 my ($fh,$l)=@_;
 my $this=$Con{$fh};
 $this->{body}.=$l;
 $this->{maillength}+=length($l);
 if ($l=~/^\.(?:\015\012)?$/ || defined($this->{bdata}) && $this->{bdata}<=0) {
  # mail summary report
  slog($fh,'('.needEs($this->{maillength},' byte','s').' received)',0,'I');
  my $nhl=(($this->{reporttype} & 4)==0) ? $NoHaikuWhitelist : $NoHaikuRedlist;
  ReturnMail($fh,'',"$this->{rcpt}\015\012\015\012$this->{report}\015\012") unless $nhl;
  delete $this->{report};
  doneStats($fh,1,'reports');
  stateReset($fh);
  sendque($this->{friend},"RSET\015\012",1);
 } elsif ($l=~/message-id:/i || $l=~/from:.*?\Q$this->{mailfrom}\E/i) {
  # ignore
 } else {
  while ($l=~/($EmailAdrRe\@$EmailDomainRe)/go) {
   listReportExec($fh,$1);
  }
 }
}

sub listReportExec {
 my ($fh,$a)=@_;
 my $this=$Con{$fh};
 my $ea=($this->{reporttype}==2) ? "$EmailWhitelistAdd\@" :
        ($this->{reporttype}==3) ? "$EmailWhitelistRemove\@" :
        ($this->{reporttype}==4) ? "$EmailRedlistAdd\@" :
                                   "$EmailRedlistRemove\@";
 return unless $a=~/($EmailAdrRe\@)$EmailDomainRe/;
 return if (lc $1 eq lc $ea) && localMailDomain($a);
 my $t=time;
 my $list=(($this->{reporttype} & 4)==0) ? 'Whitelist' : 'Redlist';
 if ($this->{reporttype} & 1) {
  # deletion
  if ($list->{lc $a}) {
   mlog(0,'email '.lc $list." deletion: $a") if $EmailInterfaceLog;
   delete $list->{lc $a};
   $this->{report}.="$a: deleted from ".lc $list."\015\012";
  } else {
   mlog(0,'email '.lc $list." miss on deletion: $a") if $EmailInterfaceLog;
   $this->{report}.="$a: not on ".lc $list."\015\012";
  }
 } else {
  # addition
  if ($list->{lc $a}) {
   mlog(0,'email '.lc $list." renewal: $a") if $EmailInterfaceLog;
   $list->{lc $a}=$t;
   $this->{report}.="$a: already on ".lc $list."\015\012";
  } elsif ($list eq 'Whitelist' && localMailDomain($a)) {
   mlog(0,"email whitelist addition denied: $a") if $EmailInterfaceLog;
   $this->{report}.="$a: cannot add local users to whitelist\015\012";
  } else {
   mlog(0,'email '.lc $list." addition: $a") if $EmailInterfaceLog;
   $list->{lc $a}=$t;
   $this->{report}.="$a: added to ".lc $list."\015\012";
  }
 }
}

sub ReturnMail {
 my ($fh,$sub,$body)=@_;
 my $s=new IO::Socket::INET(Proto=>'tcp',PeerAddr=>$smtpDestination,Timeout=>2);
 unless ($s) {
  mlog(0,"couldn't create server socket to $smtpDestination -- aborting ReturnMail connection");
  return;
 }
 addfh($s,\&RMhelo);
 my $this=$Con{$s};
 $this->{isServer}=1;
 # add SMTP session
 addSession($s);
 # set session fh (sfh)
 $this->{sfh}=$s;
 slog($s,"(connected $smtpDestination)",1,'I');
 $this->{from}=$EmailFrom;
 $this->{to}=$Con{$fh}->{mailfrom};
 my $file='data/reports/';
 $file.=($Con{$fh}->{reporttype}==0) ? 'spamreport.txt' :
        ($Con{$fh}->{reporttype}==1) ? 'notspamreport.txt' :
        ($Con{$fh}->{reporttype}==2) ? 'whitereport.txt' :
        ($Con{$fh}->{reporttype}==3) ? 'whiteremovereport.txt' :
        ($Con{$fh}->{reporttype}==4) ? 'redreport.txt' :
                                       'redremovereport.txt';
 open(F,"<$base/$file") || mlog(0,"couldn't open '$file' for mail report");
 local $/="\n";
 my $sub2=<F>;
 $sub2=~s/\s*(.*?)\s*(?:\r?\n|\r)/$1$sub/;
 undef $/;
 $this->{body}=<F>.$body;
 close F;
 $this->{body}=~s/\r?\n|\r/\015\012/g;
 my $date=$UseLocalTime ? localtime() : gmtime();
 my $tz=$UseLocalTime ? tzStr() : '+0000';
 $date=~s/(\w+) +(\w+) +(\d+) +(\S+) +(\d+)/$1, $3 $2 $5 $4/;
 $this->{header}="From: $this->{from}\015\012".
                 "To: $this->{to}\015\012".
                 "Subject: $sub2\015\012".
                 "X-Assp-Report: YES\015\012".
                 "Date: $date $tz\015\012";
}

sub RMhelo {
 my ($fh,$l);
 my $sref=$Tasks{$CurTaskID}->{RMhelo}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  slog($fh,$l,0);
  if ($l=~/^ *5/) {
   RMabort($fh,"helo Expected 220, got: $l");
  } elsif ($l=~/^ *220 /) {
   $Con{$fh}->{getline}=\&RMfrom;
   sendque($fh,"HELO $myName\015\012",1);
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub RMfrom {
 my ($fh,$l);
 my ($this,$fr);
 my $sref=$Tasks{$CurTaskID}->{RMfrom}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  slog($fh,$l,0);
  if ($l=~/^ *5/) {
   RMabort($fh,"from Expected 250, got: $l");
  } elsif ($l=~/^ *250 /) {
   $this=$Con{$fh};
   $this->{getline}=\&RMrcpt;
   $fr=$this->{from}=~/(<[^<>]+>)/ ? $1 : $this->{from};
   sendque($fh,"MAIL FROM:$fr\015\012",1);
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub RMrcpt {
 my ($fh,$l);
 my $sref=$Tasks{$CurTaskID}->{RMrcpt}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  slog($fh,$l,0);
  if ($l=~/^ *5/) {
   RMabort($fh,"rcpt Expected 250, got: $l");
  } elsif ($l=~/^ *250 /) {
   $Con{$fh}->{getline}=\&RMdata;
   sendque($fh,"RCPT TO:<$Con{$fh}->{to}>\015\012",1);
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub RMdata {
 my ($fh,$l);
 my $sref=$Tasks{$CurTaskID}->{RMdata}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  slog($fh,$l,0);
  if ($l=~/^ *5/) {
   RMabort($fh,"data Expected 250, got: $l");
  } elsif ($l=~/^ *250 /) {
   $Con{$fh}->{getline}=\&RMdata2;
   sendque($fh,"DATA\015\012",1);
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub RMdata2 {
 my ($fh,$l);
 my ($this,$s);
 my $sref=$Tasks{$CurTaskID}->{RMdata2}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  slog($fh,$l,0);
  if ($l=~/^ *5/) {
   RMabort($fh,"data2 Expected 354, got: $l");
  } elsif ($l=~/^ *354 /) {
   $this=$Con{$fh};
   $this->{indata}=1;
   $this->{getline}=\&RMdone;
   $s="$this->{header}\015\012".
      "$this->{body}\015\012.\015\012";
   sendque($fh,$s);
   slog($fh,'('.needEs(length($s),' byte','s').' sent)',1,'I');
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub RMdone {
 my ($fh,$l);
 my $this;
 my $sref=$Tasks{$CurTaskID}->{RMdone}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  slog($fh,$l,0);
  $this=$Con{$fh};
  $this->{indata}=0;
  if ($l=~/^ *5/) {
   RMabort($fh,"done Expected 250, got: $l");
  } elsif ($l=~/^ *250 /) {
   doneStats($fh,1,'reportreturns');
   $this->{getline}=\&RMquit;
   sendque($fh,"QUIT\015\012",1);
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub RMabort {
 my ($fh,$l)=@_;
 mlog(0,"RMabort: $l");
 doneStats($fh,0,'reportreturns');
 $this->{getline}=\&RMquit;
 sendque($fh,"QUIT\015\012",1);
}

sub RMquit {
 my ($fh,$l);
 my $sref=$Tasks{$CurTaskID}->{RMdone}||=[sub{
  ($fh,$l)=@_;
 },sub{&jump;
  slog($fh,$l,0);
  doneStats($fh,1);
  doneSession($fh,1);
 }];
 &{$sref->[0]};
 return $sref->[1];
}

#####################################################################################
#                Greylist functions

sub taskDownloadGrey {
 my ($s,$len,@s,$peeraddress,$connect,$buf,$fil);
 return coro(sub{&jump;
  while (1) {
   unless (!$nogreydownload && $greylist) {
    waitTaskDelay(0,60);
    return cede('L1'); L1:
    next;
   }
   # let's check if we really need to
   @s=stat("$base/$greylist");
   waitTaskDelay(0,12*3600-(time-$s[9])); # file mtime
   return cede('L2'); L2:
   ($peeraddress,$connect)=();
   if ($proxyserver) {
    mlog(0,"freshening greylist via proxy:$proxyserver") if $MaintenanceLog;
    $peeraddress=$proxyserver;
    $connect="GET http://assp.sourceforge.net/greylist.txt HTTP/1.0

";
   } else {
    mlog(0,'freshening greylist via direct connection') if $MaintenanceLog;
    $peeraddress='assp.sourceforge.net:80';
    $connect="GET /greylist.txt HTTP/1.1
Host: assp.sourceforge.net

";
   }
   $s=new IO::Socket::INET(Proto=>'tcp',PeerAddr=>$peeraddress,Timeout=>2);
   unless ($s) {
    mlog(0,'unable to connect to greylist server');
    waitTaskDelay(0,3600);
    return cede('L3'); L3:
    next;
   }
   open(GREYTEMP,">$base/$greylist.tmp");
   binmode(GREYTEMP);
   print $s $connect;
   $len=0;
   while (1) {
    waitTaskRead(0,$s,7);
    return cede('L4'); L4:
    next unless getTaskWaitResult(0);
    ($buf)=();
    unless ($s->sysread($buf,4096)>0) {
     # greylist download interrupted
     $s->close;
     close(GREYTEMP);
     mlog(0,'greylist download interrupted');
     last;
    }
    unless ($len) {
     # look for http header
     if ($buf=~/content-length: (\d+)/i) {
      $len=$1;
     }
     if ($buf=~/(.*?)\015\012\015\012(.*)/s) {
      $buf=$2;
     }
    }
    next unless $len>0;
    print GREYTEMP $buf;
    $len-=length($buf);
    next if $len;
    $s->close;
    close GREYTEMP;
    $fil="$base/$greylist";
    backupFile($fil);
    rename("$fil.tmp",$fil);
    mlog(0,'greylist download complete') if $MaintenanceLog;
    if ($GreylistObject) {
     $GreylistObject->resetCache();
    } else {
     $GreylistObject=tie %Greylist,orderedtie,"$base/$greylist" if $greylist;
    }
    last;
   }
  }
 });
}

#####################################################################################
#                Stats functions

sub taskUploadStats {
 my ($peeraddress,$connect,$s,%UploadStats,%tots,$content,$len);
 return coro(sub{&jump;
  while (1) {
   unless ($totalizeSpamStats) {
    waitTaskDelay(0,60);
    return cede('L1'); L1:
    next;
   }
   # let's check if we really need to
   waitTaskDelay(0,$Stats{nextUpload}-time);
   return cede('L2'); L2:
   ($peeraddress,$connect)=();
   if ($proxyserver) {
    mlog(0,"uploading stats via proxy:$proxyserver") if $MaintenanceLog;
    $peeraddress=$proxyserver;
    $connect='POST http://assp.sourceforge.net/cgi-bin/upload.pl HTTP/1.0';
   } else {
    mlog(0,'uploading stats via direct connection') if $MaintenanceLog;
    $peeraddress='assp.sourceforge.net:80';
    $connect="POST /cgi-bin/upload.pl HTTP/1.1
  Host: assp.sourceforge.net";
   }
   $s=new IO::Socket::INET(Proto=>'tcp',PeerAddr=>$peeraddress,Timeout=>2);
   unless ($s) {
    mlog(0,'unable to connect to stats server');
    waitTaskDelay(0,3600);
    return cede('L3'); L3:
    next;
   }
   (%UploadStats)=();
   %tots=statsTotals();
   $UploadStats{starttime}=$Stats{starttime};
   $UploadStats{version}=$Stats{version};
   $UploadStats{pid}=$$;
   $UploadStats{timenow}=time;
   $UploadStats{testmode}=unpack 'CC', pack 'B*', "$mfTestMode$malformedTestMode$uriblTestMode$baysTestMode$blTestMode$hlTestMode$sbTestMode$spfTestMode$rblTestMode$srsTestMode";
   $UploadStats{messages}=$tots{msgProcessed}; # legacy
   $UploadStats{locals}=$Stats{locals};
   $UploadStats{whites}=$Stats{whites};
   $UploadStats{noprocessing}=$Stats{noprocessing};
   # for legacy support, $UploadStats{spams} are effectively non Bayesian spams.
   $UploadStats{spams}=$tots{msgRejected}-$Stats{bspams}; # legacy
   $UploadStats{blacklisted}=$Stats{blacklisted};
   $UploadStats{helolisted}=$Stats{helolisted};
   $UploadStats{senderfails}=$Stats{senderfails};
   $UploadStats{spambucket}=$Stats{spambucket};
   $UploadStats{bhams}=$Stats{bhams};
   $UploadStats{bspams}=$Stats{bspams};
   $UploadStats{viri}=$Stats{malformed}+$Stats{viri}+$Stats{viridetected}; # legacy
   $UploadStats{viridetected}=$Stats{viridetected};
   $UploadStats{norelays}=$tots{rcptRelayRejected}; # legacy
   $UploadStats{connects}=$tots{smtpConn}; # legacy
   $UploadStats{spamlover}=$Stats{spamlover}+$Stats{testspams}; # legacy ?
   $UploadStats{bombs}=$Stats{bombs};
   $UploadStats{scripts}=$Stats{scripts};
   $UploadStats{spffails}=$Stats{spffails};
   $UploadStats{rblfails}=$Stats{rblfails};
   $UploadStats{nextUpload}=$Stats{nextUpload};
   $content=join("\001",%UploadStats);
   $len=length($content);
   $connect.="
 Content-Type: application/x-www-form-urlencoded
 Content-Length: $len

 $content";
   print $s $connect;
   $s->close;
   $Stats{nextUpload}=time+8*3600;
  }
 });
}

sub resetStats {
 $Stats{nextUpload}=time+8*3600;
 $Stats{cpuTime}=0;
 $Stats{cpuIdleTime}=0;
 $Stats{smtpConn}=0;
 $Stats{smtpConnNotLogged}=0;
 $Stats{smtpConnLimit}=0;
 $Stats{smtpConnLimitIP}=0;
 $Stats{smtpConnDenied}=0;
 $Stats{smtpConnRateLimit}=0;
 $Stats{smtpMaxConcurrentSessions}=0;
 $Stats{admConn}=0;
 $Stats{admConnDenied}=0;
 $Stats{clientHeloValidated}=0;
 $Stats{clientHeloUnchecked}=0;
 $Stats{clientHeloForged}=0;
 $Stats{clientHeloBlacklisted}=0;
 $Stats{clientHeloMismatch}=0;
 $Stats{clientHeloSpam}=0;
 $Stats{senderValidatedLocal}=0;
 $Stats{senderUncheckedLocal}=0;
 $Stats{senderWhitelisted}=0;
 $Stats{senderValidatedRemote}=0;
 $Stats{senderUncheckedRemote}=0;
 $Stats{senderUnprocessed}=0;
 $Stats{senderForged}=0;
 $Stats{senderNoMX}=0;
 $Stats{rcptValidated}=0;
 $Stats{rcptUnchecked}=0;
 $Stats{rcptSpamLover}=0;
 $Stats{rcptWhitelisted}=0;
 $Stats{rcptNotWhitelisted}=0;
 $Stats{rcptUnprocessed}=0;
 $Stats{rcptReportSpam}=0;
 $Stats{rcptReportHam}=0;
 $Stats{rcptReportWhitelistAdd}=0;
 $Stats{rcptReportWhitelistRemove}=0;
 $Stats{rcptReportRedlistAdd}=0;
 $Stats{rcptReportRedlistRemove}=0;
 $Stats{rcptNonexistent}=0;
 $Stats{rcptDelayed}=0;
 $Stats{rcptDelayedLate}=0;
 $Stats{rcptDelayedExpired}=0;
 $Stats{rcptEmbargoed}=0;
 $Stats{rcptSpamBucket}=0;
 $Stats{rcptRelayRejected}=0;
 my @mcats=('noprocessing','locals','whites','reds','bhams','spamlover','testspams','reports','bspams','helolisted','senderfails',
            'blacklisted','spambucket','spffails','rblfails','malformed','uriblfails','viri','viridetected','bombs','scripts',
            'msgNoRcpt','msgDelayed','msgNoSRSBounce','msgMaxErrors','msgEarlytalker','msgRateLimited','msgAborted');
 foreach my $m (@mcats) {
  $Stats{$m}=0;
  $Stats{"prbytes$m"}=0;
  $Stats{"prtime$m"}=0;
  $Stats{"wbytes$m"}=0;
  $Stats{"pwtime$m"}=0;
  $Stats{"drbytes$m"}=0;
  $Stats{"drtime$m"}=0;
  $Stats{"dwbytes$m"}=0;
  $Stats{"dwtime$m"}=0;
  $Stats{"lbanner$m"}=0;
  $Stats{"lmin$m"}=0;
  $Stats{"lmax$m"}=0;
 }
 my @mcats2=('ClientAccepted','other','ServerPassed','proxied','cc','reportreturns','ClientBlocked','otherblocked','ServerAborted');
 foreach my $m (@mcats2) {
  $Stats{"prbytes$m"}=0;
  $Stats{"prtime$m"}=0;
  $Stats{"pwbytes$m"}=0;
  $Stats{"pwtime$m"}=0;
  $Stats{"drbytes$m"}=0;
  $Stats{"drtime$m"}=0;
  $Stats{"dwbytes$m"}=0;
  $Stats{"dwtime$m"}=0;
  $Stats{"'lbanner$m"}=0;
  $Stats{"'lmin$m"}=0;
  $Stats{"lmax$m"}=0;
 }
 my @tcats=('ClientSMTP','ServerSMTP','RelaySMTP');
 foreach my $t (@tcats) {
  $Stats{"prbytes$t"}=0;
  $Stats{"prtime$t"}=0;
  $Stats{"pwbytes$t"}=0;
  $Stats{"pwtime$t"}=0;
  $Stats{"drbytes$t"}=0;
  $Stats{"drtime$t"}=0;
  $Stats{"dwbytes$t"}=0;
  $Stats{"dwtime$t"}=0;
 }
 foreach my $p ('RWL',@rwllist,'SPF','RBL',@rbllist,'URIBL',@uribllist) {
  $Stats{"providerQueries$p"}=0;
  $Stats{"providerReplies$p"}=0;
  $Stats{"providerHits$p"}=0;
  $Stats{"providerTime$p"}=0;
  $Stats{"providerMinTime$p"}=0;
  $Stats{"providerMaxTime$p"}=0;
 }
 $Stats{taskCreatedM}-=$Stats{taskFinishedM}; # MAIN
 $Stats{taskCreatedS}-=$Stats{taskFinishedS}; # SMTP
 $Stats{taskCreatedW}-=$Stats{taskFinishedW}; # WEB
 $Stats{taskFinishedM}=0;
 $Stats{taskFinishedS}=0;
 $Stats{taskFinishedW}=0;
 $Stats{taskCallsM}=0;
 $Stats{taskCallsS}=0;
 $Stats{taskCallsW}=0;
 $Stats{taskCallsKernel}=0;
 $Stats{taskTimeM}=0;
 $Stats{taskTimeS}=0;
 $Stats{taskTimeW}=0;
 $Stats{taskTimeKernel}=0;
 $Stats{taskTimeIdle}=0;
 $Stats{taskTimeUser}=0;
 $Stats{prtputMaxClientSMTP}=0;
 $Stats{pwtputMaxClientSMTP}=0;
 $Stats{drtputMaxClientSMTP}=0;
 $Stats{dwtputMaxClientSMTP}=0;
 $Stats{prtputMaxServerSMTP}=0;
 $Stats{pwtputMaxServerSMTP}=0;
 $Stats{drtputMaxServerSMTP}=0;
 $Stats{dwtputMaxServerSMTP}=0;
 $Stats{prtputMaxRelaySMTP}=0;
 $Stats{pwtputMaxRelaySMTP}=0;
 $Stats{drtputMaxRelaySMTP}=0;
 $Stats{dwtputMaxRelaySMTP}=0;
 $Stats{prtputMaxSMTP}=0;
 $Stats{pwtputMaxSMTP}=0;
 $Stats{drtputMaxSMTP}=0;
 $Stats{dwtputMaxSMTP}=0;
 $Stats{rtputMaxSMTP}=0;
 $Stats{wtputMaxSMTP}=0;
 $Stats{taskMaxActiveM}=0;
 $Stats{taskMaxActiveS}=0;
 $Stats{taskMaxActiveW}=0;
 $Stats{taskMaxActive}=0;
 $KernelStats{max_queue}=$Stats{taskMaxQueue}=0;
 $KernelStats{max_high_queue}=$Stats{taskMaxQueueHigh}=0;
 $KernelStats{max_norm_queue}=$Stats{taskMaxQueueNorm}=0;
 $KernelStats{max_idle_queue}=$Stats{taskMaxQueueIdle}=0;
 $KernelStats{max_wait_queue}=$Stats{taskMaxQueueWait}=0;
 $KernelStats{max_suspend_queue}=$Stats{taskMaxQueueSuspend}=0;
 open(F,"<$base/data/asspstats.sav");
 (%OldStats)=split(/\001/,<F>);
 close F;
 # conversion from previous versions
 if (exists $OldStats{messages}) {
  $OldStats{smtpConn}=$OldStats{connects};
  $OldStats{smtpConnLimit}=$OldStats{maxSMTP};
  $OldStats{smtpConnLimitIP}=$OldStats{maxSMTPip};
  $OldStats{viri}-=$OldStats{viridetected}; # fix double counting
  $OldStats{rcptRelayRejected}=$OldStats{norelays};
  # remove unused entries
  delete $OldStats{connects};
  delete $OldStats{maxSMTP};
  delete $OldStats{maxSMTPip};
  delete $OldStats{messages};
  delete $OldStats{spams};
  delete $OldStats{hams};
  delete $OldStats{norelays};
  delete $OldStats{testmode};
  saveStats();
 }
}

sub saveStats {
 my $done=shift;
 if ($done) {
  # fix finished tasks stats
  foreach my $class (keys %TaskStats) {
   $Stats{"taskFinished$class"}=$Stats{"taskCreated$class"};
  }
 }
 %AllStats=%OldStats;
 while (my ($s,$v)=each(%Stats)) {
  if ($s eq 'version') {
   # just copy
   $AllStats{$s}=$v;
  } elsif ($s=~/^(?:taskMin|providerMin)/) {
   # pick smaller non-zero value
   $AllStats{$s}=$v if $v && $v<$AllStats{$s} || !$AllStats{$s};
  } elsif ($s=~/^(?:smtpMax|taskMax|(?:p|d|)(?:r|w)tputMax|providerMax)/) {
   # pick greater value
   $AllStats{$s}=$v if $v>$AllStats{$s};
  } else {
   $AllStats{$s}+=$v;
  }
 }
 $AllStats{starttime}=$OldStats{starttime} || $Stats{starttime};
 my $fil="$base/data/asspstats.sav";
 backupFile($fil);
 open(F,">$fil");
 print F join("\001",%AllStats);
 close F;
}

# compute various totals
sub statsTotals {
 my %s;
 # smtp connections processed
 $s{smtpConnAccepted}=$Stats{smtpConn}+$Stats{smtpConnNotLogged};
 $s{smtpConnAccepted2}=$AllStats{smtpConn}+$AllStats{smtpConnNotLogged};
 $s{smtpConnLimit}=$Stats{smtpConnLimit}+$Stats{smtpConnLimitIP};
 $s{smtpConnLimit2}=$AllStats{smtpConnLimit}+$AllStats{smtpConnLimitIP};
 $s{smtpConnRejected}=$Stats{smtpConnDenied}+$Stats{smtpConnRateLimit};
 $s{smtpConnRejected2}=$AllStats{smtpConnDenied}+$AllStats{smtpConnRateLimit};
 $s{smtpConn}=$s{smtpConnAccepted}+$s{smtpConnRejected};
 $s{smtpConn2}=$s{smtpConnAccepted2}+$s{smtpConnRejected2};
 # admin connections processed
 $s{admConn}=$Stats{admConn}+$Stats{admConnDenied};
 $s{admConn2}=$AllStats{admConn}+$AllStats{admConnDenied};
 # clients processed
 $s{clientAcceptedHelo}=$Stats{clientHeloValidated}+$Stats{clientHeloUnchecked};
 $s{clientAcceptedHelo2}=$AllStats{clientHeloValidated}+$AllStats{clientHeloUnchecked};
 $s{clientAccepted}=$s{clientAcceptedHelo};
 $s{clientAccepted2}=$s{clientAcceptedHelo2};
 $s{clientRejectedHelo}=$Stats{clientHeloForged}+$Stats{clientHeloBlacklisted}+$Stats{clientHeloMismatch}+$Stats{clientHeloSpam};
 $s{clientRejectedHelo2}=$AllStats{clientHeloForged}+$AllStats{clientHeloBlacklisted}+$AllStats{clientHeloMismatch}+$AllStats{clientHeloSpam};
 $s{clientRejected}=$s{clientRejectedHelo};
 $s{clientRejected2}=$s{clientRejectedHelo2};
 $s{client}=$s{clientAccepted}+$s{clientRejected};
 $s{client2}=$s{clientAccepted2}+$s{clientRejected2};
 # senders processed
 $s{senderAcceptedLocal}=$Stats{senderValidatedLocal}+$Stats{senderUncheckedLocal};
 $s{senderAcceptedLocal2}=$AllStats{senderValidatedLocal}+$AllStats{senderUncheckedLocal};
 $s{senderAcceptedRemote}=$Stats{senderWhitelisted}+$Stats{senderValidatedRemote}+$Stats{senderUncheckedRemote};
 $s{senderAcceptedRemote2}=$AllStats{senderWhitelisted}+$AllStats{senderValidatedRemote}+$AllStats{senderUncheckedRemote};
 $s{senderUnprocessed}=$Stats{senderUnprocessed};
 $s{senderUnprocessed2}=$AllStats{senderUnprocessed};
 $s{senderAccepted}=$s{senderAcceptedLocal}+$s{senderAcceptedRemote}+$s{senderUnprocessed};
 $s{senderAccepted2}=$s{senderAcceptedLocal2}+$s{senderAcceptedRemote2}+$s{senderUnprocessed2};
 $s{senderRejectedLocal}=$Stats{senderForged};
 $s{senderRejectedLocal2}=$AllStats{senderForged};
 $s{senderRejectedRemote}=$Stats{senderNoMX};
 $s{senderRejectedRemote2}=$AllStats{senderNoMX};
 $s{senderRejected}=$s{senderRejectedLocal}+$s{senderRejectedRemote};
 $s{senderRejected2}=$s{senderRejectedLocal2}+$s{senderRejectedRemote2};
 $s{sender}=$s{senderAccepted}+$s{senderRejected};
 $s{sender2}=$s{senderAccepted2}+$s{senderRejected2};
 # recipients processed
 $s{rcptAcceptedLocal}=$Stats{rcptValidated}+$Stats{rcptUnchecked}+$Stats{rcptSpamLover};
 $s{rcptAcceptedLocal2}=$AllStats{rcptValidated}+$AllStats{rcptUnchecked}+$AllStats{rcptSpamLover};
 $s{rcptAcceptedRemote}=$Stats{rcptWhitelisted}+$Stats{rcptNotWhitelisted};
 $s{rcptAcceptedRemote2}=$AllStats{rcptWhitelisted}+$AllStats{rcptNotWhitelisted};
 $s{rcptUnprocessed}=$Stats{rcptUnprocessed};
 $s{rcptUnprocessed2}=$AllStats{rcptUnprocessed};
 $s{rcptReport}=$Stats{rcptReportSpam}+$Stats{rcptReportHam}+$Stats{rcptReportWhitelistAdd}+$Stats{rcptReportWhitelistRemove}+
                $Stats{rcptReportRedlistAdd}+$Stats{rcptReportRedlistRemove};
 $s{rcptReport2}=$AllStats{rcptReportSpam}+$AllStats{rcptReportHam}+$AllStats{rcptReportWhitelistAdd}+$AllStats{rcptReportWhitelistRemove}+
                 $AllStats{rcptReportRedlistAdd}+$AllStats{rcptReportRedlistRemove};
 $s{rcptAccepted}=$s{rcptAcceptedLocal}+$s{rcptAcceptedRemote}+$s{rcptUnprocessed}+$s{rcptReport};
 $s{rcptAccepted2}=$s{rcptAcceptedLocal2}+$s{rcptAcceptedRemote2}+$s{rcptUnprocessed2}+$s{rcptReport2};
 $s{rcptRejectedLocal}=$Stats{rcptNonexistent}+$Stats{rcptDelayed}+$Stats{rcptDelayedLate}+$Stats{rcptDelayedExpired}+
                       $Stats{rcptEmbargoed}+$Stats{rcptSpamBucket};
 $s{rcptRejectedLocal2}=$AllStats{rcptNonexistent}+$AllStats{rcptDelayed}+$AllStats{rcptDelayedLate}+$AllStats{rcptDelayedExpired}+
                        $AllStats{rcptEmbargoed}+$AllStats{rcptSpamBucket};
 $s{rcptRejectedRemote}=$Stats{rcptRelayRejected};
 $s{rcptRejectedRemote2}=$AllStats{rcptRelayRejected};
 $s{rcptRejected}=$s{rcptRejectedLocal}+$s{rcptRejectedRemote};
 $s{rcptRejected2}=$s{rcptRejectedLocal2}+$s{rcptRejectedRemote2};
 $s{rcpt}=$s{rcptAccepted}+$s{rcptRejected};
 $s{rcpt2}=$s{rcptAccepted2}+$s{rcptRejected2};
 # messages processed per message status
 $s{msgAccepted}=$Stats{noprocessing}+$Stats{locals}+$Stats{whites}+$Stats{reds}+$Stats{bhams}+$Stats{spamlover}+
                 $Stats{testspams}+$Stats{reports};
 $s{msgAccepted2}=$AllStats{noprocessing}+$AllStats{locals}+$AllStats{whites}+$AllStats{reds}+$AllStats{bhams}+
                  $AllStats{spamlover}+$AllStats{testspams}+$AllStats{reports};
 $s{msgRejected}=$Stats{bspams}+$Stats{helolisted}+$Stats{senderfails}+$Stats{blacklisted}+$Stats{spambucket}+$Stats{spffails}+
                 $Stats{rblfails}+$Stats{malformed}+$Stats{uriblfails}+$Stats{viri}+$Stats{viridetected}+
                 $Stats{bombs}+$Stats{scripts}+$Stats{msgNoRcpt}+$Stats{msgDelayed}+$Stats{msgNoSRSBounce}+
                 $Stats{msgMaxErrors}+$Stats{msgEarlytalker}+$Stats{msgRateLimited}+$Stats{msgAborted};
 $s{msgRejected2}=$AllStats{bspams}+$AllStats{helolisted}+$AllStats{senderfails}+$AllStats{blacklisted}+$AllStats{spambucket}+$AllStats{spffails}+
                  $AllStats{rblfails}+$AllStats{malformed}+$AllStats{uriblfails}+$AllStats{viri}+$AllStats{viridetected}+
                  $AllStats{bombs}+$AllStats{scripts}+$AllStats{msgNoRcpt}+$AllStats{msgDelayed}+$AllStats{msgNoSRSBounce}+
                  $AllStats{msgMaxErrors}+$AllStats{msgEarlytalker}+$AllStats{msgRateLimited}+$AllStats{msgAborted};
 $s{msgProcessed}=$s{msgAccepted}+$s{msgRejected};
 $s{msgProcessed2}=$s{msgAccepted2}+$s{msgRejected2};
 # bytes received/transmitted per side of proxy
 $s{prbytesSMTP}=$Stats{prbytesClientSMTP}+$Stats{prbytesServerSMTP}+$Stats{prbytesRelaySMTP};
 $s{prbytesSMTP2}=$AllStats{prbytesClientSMTP}+$AllStats{prbytesServerSMTP}+$AllStats{prbytesRelaySMTP};
 $s{drbytesSMTP}=$Stats{drbytesClientSMTP}+$Stats{drbytesServerSMTP}+$Stats{drbytesRelaySMTP};
 $s{drbytesSMTP2}=$AllStats{drbytesClientSMTP}+$AllStats{drbytesServerSMTP}+$AllStats{drbytesRelaySMTP};
 $s{pwbytesSMTP}=$Stats{pwbytesClientSMTP}+$Stats{pwbytesServerSMTP}+$Stats{pwbytesRelaySMTP};
 $s{pwbytesSMTP2}=$AllStats{pwbytesClientSMTP}+$AllStats{pwbytesServerSMTP}+$AllStats{pwbytesRelaySMTP};
 $s{dwbytesSMTP}=$Stats{dwbytesClientSMTP}+$Stats{dwbytesServerSMTP}+$Stats{dwbytesRelaySMTP};
 $s{dwbytesSMTP2}=$AllStats{dwbytesClientSMTP}+$AllStats{dwbytesServerSMTP}+$AllStats{dwbytesRelaySMTP};
 $s{rbytesClientSMTP}=$Stats{prbytesClientSMTP}+$Stats{drbytesClientSMTP};
 $s{rbytesClientSMTP2}=$AllStats{prbytesClientSMTP}+$AllStats{drbytesClientSMTP};
 $s{rbytesServerSMTP}=$Stats{prbytesServerSMTP}+$Stats{drbytesServerSMTP};
 $s{rbytesServerSMTP2}=$AllStats{prbytesServerSMTP}+$AllStats{drbytesServerSMTP};
 $s{rbytesRelaySMTP}=$Stats{prbytesRelaySMTP}+$Stats{drbytesRelaySMTP};
 $s{rbytesRelaySMTP2}=$AllStats{prbytesRelaySMTP}+$AllStats{drbytesRelaySMTP};
 $s{wbytesClientSMTP}=$Stats{pwbytesClientSMTP}+$Stats{dwbytesClientSMTP};
 $s{wbytesClientSMTP2}=$AllStats{pwbytesClientSMTP}+$AllStats{dwbytesClientSMTP};
 $s{wbytesServerSMTP}=$Stats{pwbytesServerSMTP}+$Stats{dwbytesServerSMTP};
 $s{wbytesServerSMTP2}=$AllStats{pwbytesServerSMTP}+$AllStats{dwbytesServerSMTP};
 $s{wbytesRelaySMTP}=$Stats{pwbytesRelaySMTP}+$Stats{dwbytesRelaySMTP};
 $s{wbytesRelaySMTP2}=$AllStats{pwbytesRelaySMTP}+$AllStats{dwbytesRelaySMTP};
 $s{rbytesSMTP}=$s{prbytesSMTP}+$s{drbytesSMTP};
 $s{rbytesSMTP2}=$s{prbytesSMTP2}+$s{drbytesSMTP2};
 $s{wbytesSMTP}=$s{pwbytesSMTP}+$s{dwbytesSMTP};
 $s{wbytesSMTP2}=$s{pwbytesSMTP2}+$s{dwbytesSMTP2};
 # messages processed per message class
## $s{msgHam}=$Stats{noprocessing}+$Stats{locals}+$Stats{whites}+$Stats{reds}+$Stats{bhams}+$Stats{reports};
## $s{msgHam2}=$AllStats{noprocessing}+$AllStats{locals}+$AllStats{whites}+$AllStats{reds}+$AllStats{bhams}+$AllStats{reports};
 $s{msgHam}=$Stats{bhams};
 $s{msgHam2}=$AllStats{bhams};
 $s{msgPassedSpam}=$Stats{spamlover}+$Stats{testspams};
 $s{msgPassedSpam2}=$AllStats{spamlover}+$AllStats{testspams};
 $s{msgBlockedSpam}=$Stats{bspams}+$Stats{helolisted}+$Stats{senderfails}+$Stats{blacklisted}+$Stats{spambucket}+$Stats{spffails}+
                    $Stats{rblfails}+$Stats{malformed}+$Stats{uriblfails}+$Stats{viri}+$Stats{viridetected}+
                    $Stats{bombs}+$Stats{scripts}+$Stats{msgNoRcpt}+$Stats{msgDelayed}+$Stats{msgNoSRSBounce}+
                    $Stats{msgMaxErrors}+$Stats{msgEarlytalker}+$Stats{msgRateLimited};
 $s{msgBlockedSpam2}=$AllStats{bspams}+$AllStats{helolisted}+$AllStats{senderfails}+$AllStats{blacklisted}+$AllStats{spambucket}+$AllStats{spffails}+
                     $AllStats{rblfails}+$AllStats{malformed}+$AllStats{uriblfails}+$AllStats{viri}+$AllStats{viridetected}+
                     $AllStats{bombs}+$AllStats{scripts}+$AllStats{msgNoRcpt}+$AllStats{msgDelayed}+$AllStats{msgNoSRSBounce}+
                     $AllStats{msgMaxErrors}+$AllStats{msgEarlytalker}+$AllStats{msgRateLimited};
 $s{msg}=$s{msgHam}+$s{msgPassedSpam}+$s{msgBlockedSpam};
 $s{msg2}=$s{msgHam2}+$s{msgPassedSpam2}+$s{msgBlockedSpam2};
 # bytes received per message class
## $s{prbytesHam}=$Stats{prbytesnoprocessing}+$Stats{prbyteslocals}+$Stats{prbyteswhites}+$Stats{prbytesreds}+$Stats{prbytesbhams}+$Stats{prbytesreports};
## $s{prbytesHam2}=$AllStats{prbytesnoprocessing}+$AllStats{prbyteslocals}+$AllStats{prbyteswhites}+$AllStats{prbytesreds}+$AllStats{prbytesbhams}+$AllStats{prbytesreports};
 $s{prbytesHam}=$Stats{prbytesbhams};
 $s{prbytesHam2}=$AllStats{prbytesbhams};
 $s{prbytesPassedSpam}=$Stats{prbytesspamlover}+$Stats{prbytestestspams};
 $s{prbytesPassedSpam2}=$AllStats{prbytesspamlover}+$AllStats{prbytestestspams};
 $s{prbytesBlockedSpam}=$Stats{prbytesbspams}+$Stats{prbytesmsgEarlytalker}+$Stats{prbyteshelolisted}+$Stats{prbytesblacklisted}+
                        $Stats{prbytesmsgNoRcpt}+$Stats{prbytesmsgDelayed}+$Stats{prbytesmsgNoSRSBounce}+$Stats{prbytesspambucket}+
                        $Stats{prbytesspffails}+$Stats{prbytesrblfails}+$Stats{prbytesmalformed}+$Stats{prbytesuriblfails}+
                        $Stats{prbytesbombs}+$Stats{prbytesscripts}+$Stats{prbytesviri}+$Stats{prbytesviridetected}+
                        $Stats{prbytesmsgMaxErrors}+$Stats{prbytesmsgRateLimited};
 $s{prbytesBlockedSpam2}=$AllStats{prbytesbspams}+$AllStats{prbytesmsgEarlytalker}+$AllStats{prbyteshelolisted}+$AllStats{prbytesblacklisted}+
                         $AllStats{prbytesmsgNoRcpt}+$AllStats{prbytesmsgDelayed}+$AllStats{prbytesmsgNoSRSBounce}+$AllStats{prbytesspambucket}+
                         $AllStats{prbytesspffails}+$AllStats{prbytesrblfails}+$AllStats{prbytesmalformed}+$AllStats{prbytesuriblfails}+
                         $AllStats{prbytesbombs}+$AllStats{prbytesscripts}+$AllStats{prbytesviri}+$AllStats{prbytesviridetected}+
                         $AllStats{prbytesmsgMaxErrors}+$AllStats{prbytesmsgRateLimited};
 $s{prbytesMsg}=$s{prbytesHam}+$s{prbytesPassedSpam}+$s{prbytesBlockedSpam};
 $s{prbytesMsg2}=$s{prbytesHam2}+$s{prbytesPassedSpam2}+$s{prbytesBlockedSpam2};
## $s{drbytesHam}=$Stats{drbytesnoprocessing}+$Stats{drbyteslocals}+$Stats{drbyteswhites}+$Stats{drbytesreds}+$Stats{drbytesbhams}+$Stats{drbytesreports};
## $s{drbytesHam2}=$AllStats{drbytesnoprocessing}+$AllStats{drbyteslocals}+$AllStats{drbyteswhites}+$AllStats{drbytesreds}+$AllStats{drbytesbhams}+$AllStats{drbytesreports};
 $s{drbytesHam}=$Stats{drbytesbhams};
 $s{drbytesHam2}=$AllStats{drbytesbhams};
 $s{drbytesPassedSpam}=$Stats{drbytesspamlover}+$Stats{drbytestestspams};
 $s{drbytesPassedSpam2}=$AllStats{drbytesspamlover}+$AllStats{drbytestestspams};
 $s{drbytesBlockedSpam}=$Stats{drbytesbspams}+$Stats{drbytesmsgEarlytalker}+$Stats{drbyteshelolisted}+$Stats{drbytesblacklisted}+
                        $Stats{drbytesmsgNoRcpt}+$Stats{drbytesmsgDelayed}+$Stats{drbytesmsgNoSRSBounce}+$Stats{drbytesspambucket}+
                        $Stats{drbytesspffails}+$Stats{drbytesrblfails}+$Stats{drbytesmalformed}+$Stats{drbytesuriblfails}+
                        $Stats{drbytesbombs}+$Stats{drbytesscripts}+$Stats{drbytesviri}+$Stats{drbytesviridetected}+
                        $Stats{drbytesmsgMaxErrors}+$Stats{drbytesmsgRateLimited};
 $s{drbytesBlockedSpam2}=$AllStats{drbytesbspams}+$AllStats{drbytesmsgEarlytalker}+$AllStats{drbyteshelolisted}+$AllStats{drbytesblacklisted}+
                         $AllStats{drbytesmsgNoRcpt}+$AllStats{drbytesmsgDelayed}+$AllStats{drbytesmsgNoSRSBounce}+$AllStats{drbytesspambucket}+
                         $AllStats{drbytesspffails}+$AllStats{drbytesrblfails}+$AllStats{drbytesmalformed}+$AllStats{drbytesuriblfails}+
                         $AllStats{drbytesbombs}+$AllStats{drbytesscripts}+$AllStats{drbytesviri}+$AllStats{drbytesviridetected}+
                         $AllStats{drbytesmsgMaxErrors}+$AllStats{drbytesmsgRateLimited};
 $s{drbytesMsg}=$s{drbytesHam}+$s{drbytesPassedSpam}+$s{drbytesBlockedSpam};
 $s{drbytesMsg2}=$s{drbytesHam2}+$s{drbytesPassedSpam2}+$s{drbytesBlockedSpam2};
 $s{rbytesHam}=$s{prbytesHam}+$s{drbytesHam};
 $s{rbytesHam2}=$s{prbytesHam2}+$s{drbytesHam2};
 $s{rbytesPassedSpam}=$s{prbytesPassedSpam}+$s{drbytesPassedSpam};
 $s{rbytesPassedSpam2}=$s{prbytesPassedSpam2}+$s{drbytesPassedSpam2};
 $s{rbytesBlockedSpam}=$s{prbytesBlockedSpam}+$s{drbytesBlockedSpam};
 $s{rbytesBlockedSpam2}=$s{prbytesBlockedSpam2}+$s{drbytesBlockedSpam2};
 $s{rbytesMsg}=$s{prbytesMsg}+$s{drbytesMsg};
 $s{rbytesMsg2}=$s{prbytesMsg2}+$s{drbytesMsg2};
 # receive time per message class
## $s{prtimeHam}=$Stats{prtimenoprocessing}+$Stats{prtimelocals}+$Stats{prtimewhites}+$Stats{prtimereds}+$Stats{prtimebhams}+$Stats{prtimereports};
## $s{prtimeHam2}=$AllStats{prtimenoprocessing}+$AllStats{prtimelocals}+$AllStats{prtimewhites}+$AllStats{prtimereds}+$AllStats{prtimebhams}+$AllStats{prtimereports};
 $s{prtimeHam}=$Stats{prtimebhams};
 $s{prtimeHam2}=$AllStats{prtimebhams};
 $s{prtimePassedSpam}=$Stats{prtimespamlover}+$Stats{prtimetestspams};
 $s{prtimePassedSpam2}=$AllStats{prtimespamlover}+$AllStats{prtimetestspams};
 $s{prtimeBlockedSpam}=$Stats{prtimebspams}+$Stats{prtimemsgEarlytalker}+$Stats{prtimehelolisted}+$Stats{prtimeblacklisted}+
                       $Stats{prtimemsgNoRcpt}+$Stats{prtimemsgDelayed}+$Stats{prtimemsgNoSRSBounce}+$Stats{prtimespambucket}+
                       $Stats{prtimespffails}+$Stats{prtimerblfails}+$Stats{prtimemalformed}+$Stats{prtimeuriblfails}+
                       $Stats{prtimebombs}+$Stats{prtimescripts}+$Stats{prtimeviri}+$Stats{prtimeviridetected}+
                       $Stats{prtimemsgMaxErrors}+$Stats{prtimemsgRateLimited};
 $s{prtimeBlockedSpam2}=$AllStats{prtimebspams}+$AllStats{prtimemsgEarlytalker}+$AllStats{prtimehelolisted}+$AllStats{prtimeblacklisted}+
                        $AllStats{prtimemsgNoRcpt}+$AllStats{prtimemsgDelayed}+$AllStats{prtimemsgNoSRSBounce}+$AllStats{prtimespambucket}+
                        $AllStats{prtimespffails}+$AllStats{prtimerblfails}+$AllStats{prtimemalformed}+$AllStats{prtimeuriblfails}+
                        $AllStats{prtimebombs}+$AllStats{prtimescripts}+$AllStats{prtimeviri}+$AllStats{prtimeviridetected}+
                        $AllStats{prtimemsgMaxErrors}+$AllStats{prtimemsgRateLimited};
 $s{prtimeMsg}=$s{prtimeHam}+$s{prtimePassedSpam}+$s{prtimeBlockedSpam};
 $s{prtimeMsg2}=$s{prtimeHam2}+$s{prtimePassedSpam2}+$s{prtimeBlockedSpam2};
## $s{drtimeHam}=$Stats{drtimenoprocessing}+$Stats{drtimelocals}+$Stats{drtimewhites}+$Stats{drtimereds}+$Stats{drtimebhams}+$Stats{drtimereports};
## $s{drtimeHam2}=$AllStats{drtimenoprocessing}+$AllStats{drtimelocals}+$AllStats{drtimewhites}+$AllStats{drtimereds}+$AllStats{drtimebhams}+$AllStats{drtimereports};
 $s{drtimeHam}=$Stats{drtimebhams};
 $s{drtimeHam2}=$AllStats{drtimebhams};
 $s{drtimePassedSpam}=$Stats{drtimespamlover}+$Stats{drtimetestspams};
 $s{drtimePassedSpam2}=$AllStats{drtimespamlover}+$AllStats{drtimetestspams};
 $s{drtimeBlockedSpam}=$Stats{drtimebspams}+$Stats{drtimemsgEarlytalker}+$Stats{drtimehelolisted}+$Stats{drtimeblacklisted}+
                       $Stats{drtimemsgNoRcpt}+$Stats{drtimemsgDelayed}+$Stats{drtimemsgNoSRSBounce}+$Stats{drtimespambucket}+
                       $Stats{drtimespffails}+$Stats{drtimerblfails}+$Stats{drtimemalformed}+$Stats{drtimeuriblfails}+
                       $Stats{drtimebombs}+$Stats{drtimescripts}+$Stats{drtimeviri}+$Stats{drtimeviridetected}+
                       $Stats{drtimemsgMaxErrors}+$Stats{drtimemsgRateLimited};
 $s{drtimeBlockedSpam2}=$AllStats{drtimebspams}+$AllStats{drtimemsgEarlytalker}+$AllStats{drtimehelolisted}+$AllStats{drtimeblacklisted}+
                        $AllStats{drtimemsgNoRcpt}+$AllStats{drtimemsgDelayed}+$AllStats{drtimemsgNoSRSBounce}+$AllStats{drtimespambucket}+
                        $AllStats{drtimespffails}+$AllStats{drtimerblfails}+$AllStats{drtimemalformed}+$AllStats{drtimeuriblfails}+
                        $AllStats{drtimebombs}+$AllStats{drtimescripts}+$AllStats{drtimeviri}+$AllStats{drtimeviridetected}+
                        $AllStats{drtimemsgMaxErrors}+$AllStats{drtimemsgRateLimited};
 $s{drtimeMsg}=$s{drtimeHam}+$s{drtimePassedSpam}+$s{drtimeBlockedSpam};
 $s{drtimeMsg2}=$s{drtimeHam2}+$s{drtimePassedSpam2}+$s{drtimeBlockedSpam2};
 $s{rtimeHam}=$s{prtimeHam}+$s{drtimeHam};
 $s{rtimeHam2}=$s{prtimeHam2}+$s{drtimeHam2};
 $s{rtimePassedSpam}=$s{prtimePassedSpam}+$s{drtimePassedSpam};
 $s{rtimePassedSpam2}=$s{prtimePassedSpam2}+$s{drtimePassedSpam2};
 $s{rtimeBlockedSpam}=$s{prtimeBlockedSpam}+$s{drtimeBlockedSpam};
 $s{rtimeBlockedSpam2}=$s{prtimeBlockedSpam2}+$s{drtimeBlockedSpam2};
 $s{rtimeMsg}=$s{prtimeMsg}+$s{drtimeMsg};
 $s{rtimeMsg2}=$s{prtimeMsg2}+$s{drtimeMsg2};
 # banner latency per message class
## $s{lbannerHam}=$Stats{lbannernoprocessing}+$Stats{lbannerlocals}+$Stats{lbannerwhites}+$Stats{lbannerreds}+$Stats{lbannerbhams}+$Stats{lbannerreports};
## $s{lbannerHam2}=$AllStats{lbannernoprocessing}+$AllStats{lbannerlocals}+$AllStats{lbannerwhites}+$AllStats{lbannerreds}+$AllStats{lbannerbhams}+$AllStats{lbannerreports};
 $s{lbannerHam}=$Stats{lbannerbhams};
 $s{lbannerHam2}=$AllStats{lbannerbhams};
 $s{lbannerPassedSpam}=$Stats{lbannerspamlover}+$Stats{lbannertestspams};
 $s{lbannerPassedSpam2}=$AllStats{lbannerspamlover}+$AllStats{lbannertestspams};
 $s{lbannerBlockedSpam}=$Stats{lbannerbspams}+$Stats{lbannermsgEarlytalker}+$Stats{lbannerhelolisted}+$Stats{lbannerblacklisted}+
                        $Stats{lbannermsgNoRcpt}+$Stats{lbannermsgDelayed}+$Stats{lbannermsgNoSRSBounce}+$Stats{lbannerspambucket}+
                        $Stats{lbannerspffails}+$Stats{lbannerrblfails}+$Stats{lbannermalformed}+$Stats{lbanneruriblfails}+
                        $Stats{lbannerbombs}+$Stats{lbannerscripts}+$Stats{lbannerviri}+$Stats{lbannerviridetected}+
                        $Stats{lbannermsgMaxErrors}+$Stats{lbannermsgRateLimited};
 $s{lbannerBlockedSpam2}=$AllStats{lbannerbspams}+$AllStats{lbannermsgEarlytalker}+$AllStats{lbannerhelolisted}+$AllStats{lbannerblacklisted}+
                         $AllStats{lbannermsgNoRcpt}+$AllStats{lbannermsgDelayed}+$AllStats{lbannermsgNoSRSBounce}+$AllStats{lbannerspambucket}+
                         $AllStats{lbannerspffails}+$AllStats{lbannerrblfails}+$AllStats{lbannermalformed}+$AllStats{lbanneruriblfails}+
                         $AllStats{lbannerbombs}+$AllStats{lbannerscripts}+$AllStats{lbannerviri}+$AllStats{lbannerviridetected}+
                         $AllStats{lbannermsgMaxErrors}+$AllStats{lbannermsgRateLimited};
 $s{lbanner}=$s{lbannerHam}+$s{lbannerPassedSpam}+$s{lbannerBlockedSpam};
 $s{lbanner2}=$s{lbannerHam2}+$s{lbannerPassedSpam2}+$s{lbannerBlockedSpam2};
 # min latency per message class
## $s{lminHam}=$Stats{lminnoprocessing}+$Stats{lminlocals}+$Stats{lminwhites}+$Stats{lminreds}+$Stats{lminbhams}+$Stats{lminreports};
## $s{lminHam2}=$AllStats{lminnoprocessing}+$AllStats{lminlocals}+$AllStats{lminwhites}+$AllStats{lminreds}+$AllStats{lminbhams}+$AllStats{lminreports};
 $s{lminHam}=$Stats{lminbhams};
 $s{lminHam2}=$AllStats{lminbhams};
 $s{lminPassedSpam}=$Stats{lminspamlover}+$Stats{lmintestspams};
 $s{lminPassedSpam2}=$AllStats{lminspamlover}+$AllStats{lmintestspams};
 $s{lminBlockedSpam}=$Stats{lminbspams}+$Stats{lminmsgEarlytalker}+$Stats{lminhelolisted}+$Stats{lminblacklisted}+
                     $Stats{lminmsgNoRcpt}+$Stats{lminmsgDelayed}+$Stats{lminmsgNoSRSBounce}+$Stats{lminspambucket}+
                     $Stats{lminspffails}+$Stats{lminrblfails}+$Stats{lminmalformed}+$Stats{lminuriblfails}+
                     $Stats{lminbombs}+$Stats{lminscripts}+$Stats{lminviri}+$Stats{lminviridetected}+
                     $Stats{lminmsgMaxErrors}+$Stats{lminmsgRateLimited};
 $s{lminBlockedSpam2}=$AllStats{lminbspams}+$AllStats{lminmsgEarlytalker}+$AllStats{lminhelolisted}+$AllStats{lminblacklisted}+
                      $AllStats{lminmsgNoRcpt}+$AllStats{lminmsgDelayed}+$AllStats{lminmsgNoSRSBounce}+$AllStats{lminspambucket}+
                      $AllStats{lminspffails}+$AllStats{lminrblfails}+$AllStats{lminmalformed}+$AllStats{lminuriblfails}+
                      $AllStats{lminbombs}+$AllStats{lminscripts}+$AllStats{lminviri}+$AllStats{lminviridetected}+
                      $AllStats{lminmsgMaxErrors}+$AllStats{lminmsgRateLimited};
 $s{lmin}=$s{lminHam}+$s{lminPassedSpam}+$s{lminBlockedSpam};
 $s{lmin2}=$s{lminHam2}+$s{lminPassedSpam2}+$s{lminBlockedSpam2};
 # max latency per message class
## $s{lmaxHam}=$Stats{lmaxnoprocessing}+$Stats{lmaxlocals}+$Stats{lmaxwhites}+$Stats{lmaxreds}+$Stats{lmaxbhams}+$Stats{lmaxreports};
## $s{lmaxHam2}=$AllStats{lmaxnoprocessing}+$AllStats{lmaxlocals}+$AllStats{lmaxwhites}+$AllStats{lmaxreds}+$AllStats{lmaxbhams}+$AllStats{lmaxreports};
 $s{lmaxHam}=$Stats{lmaxbhams};
 $s{lmaxHam2}=$AllStats{lmaxbhams};
 $s{lmaxPassedSpam}=$Stats{lmaxspamlover}+$Stats{lmaxtestspams};
 $s{lmaxPassedSpam2}=$AllStats{lmaxspamlover}+$AllStats{lmaxtestspams};
 $s{lmaxBlockedSpam}=$Stats{lmaxbspams}+$Stats{lmaxmsgEarlytalker}+$Stats{lmaxhelolisted}+$Stats{lmaxblacklisted}+
                     $Stats{lmaxmsgNoRcpt}+$Stats{lmaxmsgDelayed}+$Stats{lmaxmsgNoSRSBounce}+$Stats{lmaxspambucket}+
                     $Stats{lmaxspffails}+$Stats{lmaxrblfails}+$Stats{lmaxmalformed}+$Stats{lmaxuriblfails}+
                     $Stats{lmaxbombs}+$Stats{lmaxscripts}+$Stats{lmaxviri}+$Stats{lmaxviridetected}+
                     $Stats{lmaxmsgMaxErrors}+$Stats{lmaxmsgRateLimited};
 $s{lmaxBlockedSpam2}=$AllStats{lmaxbspams}+$AllStats{lmaxmsgEarlytalker}+$AllStats{lmaxhelolisted}+$AllStats{lmaxblacklisted}+
                      $AllStats{lmaxmsgNoRcpt}+$AllStats{lmaxmsgDelayed}+$AllStats{lmaxmsgNoSRSBounce}+$AllStats{lmaxspambucket}+
                      $AllStats{lmaxspffails}+$AllStats{lmaxrblfails}+$AllStats{lmaxmalformed}+$AllStats{lmaxuriblfails}+
                      $AllStats{lmaxbombs}+$AllStats{lmaxscripts}+$AllStats{lmaxviri}+$AllStats{lmaxviridetected}+
                      $AllStats{lmaxmsgMaxErrors}+$AllStats{lmaxmsgRateLimited};
 $s{lmax}=$s{lmaxHam}+$s{lmaxPassedSpam}+$s{lmaxBlockedSpam};
 $s{lmax2}=$s{lmaxHam2}+$s{lmaxPassedSpam2}+$s{lmaxBlockedSpam2};
 # misc task stats
 $s{taskTime}=$Stats{taskTimeKernel}+$Stats{taskTimeIdle}+$Stats{taskTimeUser};
 $s{taskTime2}=$AllStats{taskTimeKernel}+$AllStats{taskTimeIdle}+$AllStats{taskTimeUser};
 $s{taskCreated}=$Stats{taskCreatedM}+$Stats{taskCreatedS}+$Stats{taskCreatedW};
 $s{taskCreated2}=$AllStats{taskCreatedM}+$AllStats{taskCreatedS}+$AllStats{taskCreatedW};
 $s{taskFinished}=$Stats{taskFinishedM}+$Stats{taskFinishedS}+$Stats{taskFinishedW};
 $s{taskFinished2}=$AllStats{taskFinishedM}+$AllStats{taskFinishedS}+$AllStats{taskFinishedW};
 $s{taskCalls}=$Stats{taskCallsM}+$Stats{taskCallsS}+$Stats{taskCallsW};
 $s{taskCalls2}=$AllStats{taskCallsM}+$AllStats{taskCallsS}+$AllStats{taskCallsW};
 return %s;
}

#####################################################################################
#                logging functions

sub mlogCond {
 my ($fh,$message,$condition)=@_;
 if ($fh && $Con{$fh} && $Con{$fh}->{simulating}) {
  mlogSim($fh,$message,$condition);
 } elsif ($condition) {
  mlog($fh,$message);
 }
}

sub mlogSim {
 my ($fh,$message,$condition)=@_;
 my $m=localtime();
 $m=~s/^... (...) +(\d+) (\S+) ..(..)/$1-$2-$4 $3 /;
 my $indent=' ' x length($m); # calculate indent
 my $ip;
 $ip="$Con{$fh}->{ip} " if $Con{$fh}->{inenvelope};
 my $from;
 $from="<$Con{$fh}->{mailfrom}> " if $Con{$fh}->{inmailfrom};
 my ($to)=$Con{$fh}->{rcpt}=~/(\S+)/;
 $to="to: $to " if $to;
 my $pre="$ip$from$to";
 $m.=$pre ? "$pre- $message" : ucfirst($message);
 $m.="\n";
 $m=encodeHTMLEntities($m);
 $m=logWrap($m,$MaillogTailWrapColumn,$indent) if $MaillogTailWrapColumn>0;
 # dim not logged lines
 $m=~s/(.*)\n$/<span class="context">$1<\/span>\n/s unless $condition;
 $SMTPSessions{$fh}->{mlogbuf}.=$m;
}

sub mlog{
 my ($fh,$message)=@_;
 my $m=localtime();
 $m=~s/^... (...) +(\d+) (\S+) ..(..)/$1-$2-$4 $3 /;
 my $indent=' ' x length($m); # calculate indent
 if ($LogRollDays>0) {
  # calculate the time difference in seconds
  my $offset=Time::Local::timelocal(localtime())-Time::Local::timelocal(gmtime());
  # roll log every $LogRollDays days, at midnight
  my $rollTime=int((time()+$offset)/($LogRollDays*86400));
  if ($logfile && $mlogLastT && $rollTime!=$mlogLastT && $logfile!~/maillog\.log$/i) {
   if ($LogRotateCopies) {
    # rotate the mail log
    close LOG;
    my $i=$LogRotateCopies-1;
    unlink("$base/$logfile.$i");
    for (;$i>0;$i--) { rename("$base/$logfile.".($i-1),"$base/$logfile.$i"); }
    rename("$base/$logfile","$base/$logfile.0");
    if (open(LOG,">>$base/$logfile")) {
     my $oldfh=select(LOG); $|=1; select($oldfh);
    }
   } else {
    # roll the mail log
    my ($sec,$min,$hour,$mday,$mon,$year)=localtime();
    $mon++; $year-=100;
    my $mm=sprintf("%02d-%02d-%02d",$year,$mon,$mday);
    $mm.=sprintf("-%02d",$hour) unless int($LogRollDays)==$LogRollDays;
    my $archivelogfile=$logfile; $archivelogfile=~s/(.*[\\\/]|)/$1$mm\./;
    my $msg=$m."Rolling log file -- archive saved as '$archivelogfile'\n";
    print LOG $msg;
    print $msg unless $silent;
    close LOG;
    rename("$base/$logfile", "$base/$archivelogfile");
    if (open(LOG,">>$base/$logfile")) {
     my $oldfh=select(LOG); $|=1; select($oldfh);
    }
    print LOG $m."New log file -- old log file renamed to '$archivelogfile'\n";
   }
   configSave();
  }
  $mlogLastT=$rollTime;
 }
 if ($fh && $Con{$fh}) {
  my $ip;
  $ip="$Con{$fh}->{ip} " if $Con{$fh}->{inenvelope};
  my $from;
  $from="<$Con{$fh}->{mailfrom}> " if $Con{$fh}->{inmailfrom};
  my ($to)=$Con{$fh}->{rcpt}=~/(\S+)/;
  $to="to: $to " if $to;
  my $pre="$ip$from$to";
  $m.=$pre ? "$pre- $message" : ucfirst($message);
 } else {
  $m.=ucfirst($message);
 }
 $m.="\n";
 return if $fh && $Con{$fh} && $Con{$fh}->{mNLOGRE};
 print logWrap($m,40,$indent) unless $silent;
 print LOG $m if $logfile;
}

sub slog {
 my ($fh,$message,$direction,$facility)=@_;
 return unless $fh && $Con{$fh};
 my $sfh=$Con{$fh}->{sfh};
 return unless $sfh && $SMTPSessions{$sfh};
 unless ($Con{$sfh}->{simulating}) {
  return if $Con{$sfh}->{mNLOGRE};
 }
 if ($ServerSessionLog) {
  $facility||=($Con{$fh}->{isClient} ? 'C' : 'S');
 } else {
  return if $Con{$fh}->{isServer};
  $facility='';
 }
 $facility.=' ' if $facility;
 my $m=localtime();
 $m=~s/^... (...) +(\d+) (\S+) ..(..)/$1-$2-$4 $3 /;
 $message=~s/\015?\012|\015//g;
 if ($Con{$sfh}->{simulating}) {
  # calculate indent
  my $indent=' ' x length($m);
  # increase indent if operating on session log
  $indent.=' ' x ($ServerSessionLog ? 5 : 3);
  $m="$m$facility".($direction ? '<- ' : '-> ')."$message\n";
  $m=encodeHTMLEntities($m);
  $m=logWrap($m,$MaillogTailWrapColumn,$indent) if $MaillogTailWrapColumn>0;
 } else {
  $m="$m$facility".($direction ? '<- ' : '-> ')."$message\n";
 }
 $SMTPSessions{$sfh}->{slogbuf}.=$m;
}

sub dumpSlog {
 my $sfh=shift;
 if ($LogRollDays>0) {
  # calculate the time difference in seconds
  my $offset=Time::Local::timelocal(localtime())-Time::Local::timelocal(gmtime());
  # roll sessions log every $LogRollDays days, at midnight
  my $rollTime=int((time()+$offset)/($LogRollDays*86400));
  if ($slogfile && $slogLastT && $rollTime!=$slogLastT && $slogfile!~/sesslog\.log$/i) {
   if ($LogRotateCopies) {
    # rotate the sessions log
    close SLOG;
    my $i=$LogRotateCopies-1;
    unlink("$base/$slogfile.$i");
    for (;$i>0;$i--) { rename("$base/$slogfile.".($i-1),"$base/$slogfile.$i"); }
    rename("$base/$slogfile","$base/$slogfile.0");
    if (open(SLOG,">>$base/$slogfile")) {
     my $oldfh=select(SLOG); $|=1; select($oldfh);
    }
   } else {
    # roll the sessions log
    my ($sec,$min,$hour,$mday,$mon,$year)=localtime();
    $mon++; $year-=100;
    my $mm=sprintf("%02d-%02d-%02d",$year,$mon,$mday);
    $mm.=sprintf("-%02d",$hour) unless int($LogRollDays)==$LogRollDays;
    my $archiveslogfile=$slogfile; $archiveslogfile=~s/(.*[\\\/]|)/$1$mm\./;
    my $msg=$m."Rolling session log file -- archive saved as '$archiveslogfile'\n";
    print SLOG $msg;
    print $msg unless $silent;
    close SLOG;
    rename("$base/$slogfile", "$base/$archiveslogfile");
    if (open(LOG,">>$base/$slogfile")) {
     my $oldfh=select(SLOG); $|=1; select($oldfh);
    }
    print SLOG $m."New session log file -- old session log file renamed to '$archiveslogfile'\n";
   }
   configSave();
  }
  $slogLastT=$rollTime;
 }
 if ($slogfile && $SMTPSessions{$sfh}->{slogbuf}) {
  print SLOG $SMTPSessions{$sfh}->{slogbuf};
  my $mid=' session '.$SMTPSessions{$sfh}->{id}.' end ';
  my $len=$MaillogTailWrapColumn ? int(($MaillogTailWrapColumn+13-length($mid))/2) : 32; # 13=(11+15)/2 from logWrap()
  $len=0 if $len<0;
  print SLOG ('-' x $len).$mid.('-' x $len)."\n";
 }
}

#####################################################################################
#                maintenance functions

sub saveDatabases {
 my $done;
 my (@objs,$n,$obj);
 my $sref=$Tasks{$CurTaskID}->{saveDatabases}||=[sub{
  $done=shift;
 },sub{&jump;
  mlog(0,'saving databases') if $MaintenanceLog;
  @objs=($WhitelistObject,$RedlistObject,$DelayObject,$DelayWhiteObject,$RateLimitObject,$CorpusObject);
  for ($n=0;$n<@objs;$n++) {
   $obj=$objs[$n];
   return cede('L1') unless $done; L1:
   $obj->flush() if $obj;
  }
  saveStats($done);
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub cleanDelayDB {
 my ($t,$kb,$kd,$k,$v);
 my $sref=$Tasks{$CurTaskID}->{cleanDelayDB}||=[sub{
 },sub{&jump;
  return unless $EnableDelaying;
  mlog(0,'cleaning up delaying databases ...') if $MaintenanceLog;
  $t=time;
  $kb=$kd=0;
  while (($k,$v)=each(%Delay)) {
   return cede('L1',8); L1:
   $kb++;
   if ($t-$v>=$DelayEmbargoTime*60+$DelayWaitTime*3600) {
    delete $Delay{$k};
    $kd++;
   }
  }
  mlog(0,"cleaning delaying database (triplets) finished; keys before=$kb, deleted=$kd") if $MaintenanceLog;
  $kb=$kd=0;
  while (($k,$v)=each(%DelayWhite)) {
   return cede('L2',8); L2:
   $kb++;
   if ($t-$v>=$DelayExpiryTime*86400) {
    delete $DelayWhite{$k};
    $kd++;
   }
  }
  mlog(0,"cleaning delaying database (whitelisted tuplets) finished; keys before=$kb, deleted=$kd") if $MaintenanceLog;
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub cleanRateLimitDB {
 my ($interval,$event,$t,$kb,$kd,$rd,$ip,$recs,@in,$added);
 my ($blocked,$reason,$since,@out,$s,$rec_added,$rec_id,$expires);
 my $sref=$Tasks{$CurTaskID}->{cleanRateLimitDB}||=[sub{
 },sub{&jump;
  return unless $EnableRateLimit;
  mlog(0,'cleaning up rate-limit database ...') if $MaintenanceLog;
  # find longest interval
  $interval=0;
  foreach $event (values %ConfigRateLimitEvents) {
   next unless $event->{limit};
   $interval=$event->{interval} if $event->{interval}>$interval;
  }
  $t=time;
  $kb=$kd=$rd=0;
  while (($ip,$recs)=each(%RateLimit)) {
   return cede('L1',8); L1:
   $kb++;
   @in=split("\003",$recs);
   ($added,$blocked,$reason)=split("\004",shift @in);
   $since=$t-$interval-$added;
   (@out)=();
   foreach $s (@in) {
    ($rec_added,$rec_id)=split("\004",$s);
    if ($rec_added>$since) {
     push(@out,$s);
    } else {
     $rd++;
    }
   }
   # check if block time expired
   if ($blocked>=0 && $reason>=0) {
    $expires=$added+$blocked+$ConfigRateLimitEvents{$reason}->{block}-$t;
    ($blocked,$reason)=(-1)x2 if $expires<0;
   }
   if ($blocked<0 && !@out) {
    # delete old entry
    delete $RateLimit{$ip};
    $kd++;
   } else {
    # update entry
    $RateLimit{$ip}="$added\004$blocked\004$reason\003";
    $RateLimit{$ip}.=join("\003",@out)."\003" if @out;
   }
  }
  mlog(0,"cleaning rate-limit database finished; keys before=$kb, deleted=$kd, records deleted=$rd") if $MaintenanceLog;
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub check4update {
 # only check every 15 seconds
 my $fil=shift;
 return if $check4updateTime{$fil}+15>time;
 $check4updateTime{$fil}=time;
 my @s=stat(${$fil});
 my $mtime=$s[9];
 if ($mtime!=$FileUpdate{$fil}) {
  # reload
  $FileUpdate{$fil}=$mtime;
  open(F,"<${$fil}");
  local $/="\n";
  my $l; my %h;
  while ($l=<F>) {
   $l=~tr/\r\n\t //d;
   next unless $l;
   $h{lc $l}=1;
  }
  close F;
  %{$fil}=%h;
 }
}

#####################################################################################
#                helper functions

sub getUidGid {
 return if $AsAService;
 my ($uname,$gname)=@_;
 eval{getgrnam(root); getpwnam(root)};
 if ($@) {
  # windows pukes 'unimplemented' for these -- just skip it
  mlog(0,"warning: uname and/or gname are set ($uname,$gname) but getgrnam / getpwnam give errors: $@");
  return;
 }
 my $gid;
 if ($gname) {
  $gid=getgrnam($gname);
  if (defined $gid) {
  } else {
   my $msg="could not find gid for group '$gname' -- not switching effective gid -- quitting";
   mlog(0,$msg);
   die ucfirst($msg);
  }
 }
 my $uid;
 if ($uname) {
  $uid=getpwnam($uname);
  if (defined $uid) {
  } else {
   my $msg="could not find uid for user '$uname' -- not switching effective uid -- quitting";
   mlog(0,$msg);
   die ucfirst($msg);
  }
 }
 ($uid,$gid);
}

sub switchUsers {
 return if $AsAService;
 my ($uid,$gid)=@_;
 my ($uname,$gname)=($runAsUser,$runAsGroup);
 $>=0;
 if ($>!=0) {
  my $msg="requested to switch to user/group '$uname/$gname' but cannot set effective uid to 0 -- quitting; uid is $>";
  mlog(0,$msg);
  die ucfirst($msg);
 }
 $<=0;
 if ($gid) {
  $)=$gid;
  if ($)+0==$gid) {
   mlog(0,"switched effective gid to $gid ($gname)");
  } else {
   my $msg="failed to switch effective gid to $gid ($gname) -- effective gid=$) -- quitting";
   mlog(0,$msg);
   die ucfirst($msg);
  }
  $(=$gid;
  if ($(+0==$gid) {
   mlog(0,"switched real gid to $gid ($gname)");
  } else {
   mlog(0,"failed to switch real gid to $gid ($gname) -- real uid=$(");
  }
 }
 if ($uid) {
  # do it both ways so linux and bsd are happy
  $<=$uid; $>=$uid; $<=$uid; $>=$uid;
  if ($>==$uid) {
  mlog(0,"switched effective uid to $uid ($uname)");
  } else {
   my $msg="failed to switch effective uid to $uid ($uname) -- real uid=$< -- quitting";
   mlog(0,$msg);
   die ucfirst($msg);
  }
  if ($<==$uid) {
   mlog(0,"switched real uid to $uid ($uname)");
  } else {
   mlog(0,"failed to switch real uid to $uid ($uname) -- real uid=$<");
  }
 }
}

sub newListen {
 my ($port,$handler)=@_;
 my ($interface,$p)=$port=~/(.*):(.*)/;
 my $s;
 if ($interface) {
  $s=new IO::Socket::INET(Listen => 10, LocalPort => $p, Reuse=>1, LocalAddr => $interface);
 } else {
  $s=new IO::Socket::INET(Listen => 10, LocalPort => $port, Reuse=>1);
 }
 unless ($s) {
  mlog(0,"couldn't create server socket on port '$port' -- maybe another service is running or I'm not root (uid=$>)?");
  return undef;
 }
 return $s;
}

sub openDatabases {
 my $force=shift;
 # put this after chroot so the paths don't change
 if ($ConfigChanged{spamdb} || $force) {
  if ($spamdb) {
   mlog(0,"warning: Bayesian spam database is small or empty: '$base/$spamdb'") if -s "$base/$spamdb"<10000;
   $SpamdbObject=tie %Spamdb,orderedtie,"$base/$spamdb";
   $HeloBlackObject=tie %HeloBlack,orderedtie,"$base/$spamdb.helo";
  } else {
   untie %Spamdb;
   untie %HeloBlack;
   undef $SpamdbObject;
   undef $HeloBlackObject;
  }
 }
 if ($ConfigChanged{dnsbl} || $force) {
  if ($dnsbl) {
   mlog(0,"warning: DNS blacklist database is small or empty: '$base/$dnsbl'") if -s "$base/$dnsbl"<10000;
   $DnsblObject=tie %Dnsbl,orderedtie,"$base/$dnsbl";
  } else {
   untie %Dnsbl;
   undef $DnsblObject;
  }
 }
 if ($ConfigChanged{whitelistdb} || $force) {
  if ($whitelistdb) {
   mlog(0,"warning: whitelist is small or empty: '$base/$whitelistdb' (ignore if this is a new install)") if -s "$base/$whitelistdb"<1000;
   $WhitelistObject=tie %Whitelist,orderedtie,"$base/$whitelistdb";
  }
 }
 if ($ConfigChanged{redlistdb} || $force) {
  $RedlistObject=tie %Redlist,orderedtie,"$base/$redlistdb" if $redlistdb;
 }
 if ($ConfigChanged{greylist} || $force) {
  if ($greylist) {
   $GreylistObject=tie %Greylist,orderedtie,"$base/$greylist";
  } else {
   untie %Greylist;
   undef $GreylistObject;
  }
 }
 if ($ConfigChanged{delaydb} || $force) {
  if ($delaydb) {
   $DelayObject=tie %Delay,orderedtie,"$base/$delaydb";
   $DelayWhiteObject=tie %DelayWhite,orderedtie,"$base/$delaydb.white";
  }
 }
 if ($ConfigChanged{ratelimitdb} || $force) {
  $RateLimitObject=tie %RateLimit,orderedtie,"$base/$ratelimitdb" if $ratelimitdb;
 }
 if ($ConfigChanged{corpusdb} || $ConfigChanged{EnableCorpusInterface} || $force) {
  if ($corpusdb && $EnableCorpusInterface) {
   $CorpusObject=tie %Corpus,orderedtie,"$base/$corpusdb";
  } else {
   untie %Corpus;
   undef $CorpusObject;
  }
 }
}

# called on SIG HUP
sub configReload {
 my %newConfig;
 mlog(0,'reloading config');
 open(F,"<$base/assp.cfg");
 local $/;
 (%newConfig)=split(/:=|\n/,<F>);
 close F;
 foreach my $c (@Config) {
  my ($name,$nicename,$size,$func,$default,$valid,$onchange,$description,$data)=@$c;
  if ($Config{$name} ne $newConfig{$name}) {
   if ($newConfig{$name}=~/$valid/i) {
    my $new=$1;
    my $info;
    if ($onchange) {
     $info=$onchange->($name,$Config{$name},$new);
    } else {
     mlog(0,"admin update: $name changed from '$Config{$name}' to '$new'");
     # -- this sets the variable name with the same name as the config key to the new value
     # -- for example $Config{myName}='ASSP-nospam' -> $myName='ASSP-nospam';
     ${$name}=$new;
    }
    $Config{$name}=$new;
   } else {
    mlog(0,"error: invalid '$newConfig{$name}' -- not changed");
   }
  }
 }
 optionFilesReload();
 if ($logfile) {
  # reopen log file, just for fun.
  close LOG;
  if (open(LOG,">>$base/$logfile")) {
   my $oldfh=select(LOG); $|=1; select($oldfh);
  }
  mlog(0,'logfile reopened');
 }
 if ($slogfile) {
  # reopen sessions log file
  close SLOG;
  if (open(SLOG,">>$base/$slogfile")) {
   my $oldfh=select(SLOG); $|=1; select($oldfh);
  }
  mlog(0,'sessions logfile reopened');
 }
}

sub ok2Relay {
 my $fh=shift;
 my $this=$Con{$fh};
 return 1 if $this->{mAMRE};
 my $ip=$this->{ip};
 if ($relayHostFile) {
  check4update(relayHostFile);
  return 1 if $relayHostFile{$ip};
 }
 return 1 if PopB4SMTP($ip);
 # failed all tests -- return 0
 return 0;
}

sub PopB4SMTP {
 return 0 unless $PopB4SMTPFile;
 unless ($TriedDBFileUse) {
  eval('use DB_File');
  mlog(0,"could not load module DB_File: $@") if $@;
  $TriedDBFileUse=1;
 }
 my $ip=shift;
 my %hash;
 tie %hash, 'DB_File', $PopB4SMTPFile, O_READ, 0400, $DB_HASH;
 if ($hash{$ip}) {
  return 1;
 } else {
  return 0;
 }
}

sub tzStr {
 # calculate the time difference in minutes
 my $minoffset=(Time::Local::timelocal(localtime())-Time::Local::timelocal(gmtime()))/60;
 # translate it to 'hour-format', so that 90 will be 130, and -90 will be -130
 my $tzoffset=int($minoffset/60)*100+sgn($minoffset)*($minoffset%60);
 # apply final formatting, including +/- sign and 4 digits
 return sprintf("%+05d", $tzoffset);
}

sub fileUpdated {
 my $fil=shift;
 $fil="$base/$fil" if $fil!~/^\Q$base\E/i;
 return 1 unless $FileUpdate{$fil};
 my @s=stat($fil);
 my $mtime=$s[9];
 $FileUpdate{$fil}!=$mtime;
}

sub createPid {
 return unless $pidfile;
 open(F,">$base/$pidfile");
 print F $$;
 close F;
}

sub removePid {
 unlink("$base/$pidfile") if $pidfile;
}

sub restart {
 my $sref=$Tasks{$CurTaskID}->{restart}||=[sub{
 },sub{&jump;
  mlog(0,'restarting');
  doneAllTasks();
  saveDatabases(1)->();
  if ($AsAService) {
   exec('cmd.exe /C net stop ASSPSMTP & net start ASSPSMTP');
  } else {
   exit 1;
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

#####################################################################################
#                corpus functions

# corpus files cached hash
# key: file name
# value fields, separated by \003:
#  mtime, subject, from, to, flags 
# flags is a 4-bits field:
#  1st bit->'seen', 2nd bit->'file-moved', 3rd bit->'is-spam', 4th bit->'passed-message'
#  if 3rd and 4th bits are both 0, the state of the message is unknown
sub corpus {
 return unless $EnableCorpusInterface;
 my ($fn,$force)=@_;
## PeekLoop(); # ProcessMessages
 if ($force || !exists ($Corpus{$fn})) {
  if (-f "$base/$fn") {
   $Corpus{$fn}=[stat("$base/$fn")]->[9]; # clear other fields (subject,from,to,flags)
  } else {
   delete $Corpus{$fn};
   return [undef];
  }
 }
 my @arr=split("\003",$Corpus{$fn});
 return \@arr;
}

sub corpusDetails {
 return unless $EnableCorpusInterface;
 my ($fn,$force)=@_;
 my $c=corpus($fn,$force);
 return [undef] unless defined $c->[0];
 if ($force || !defined ($c->[1])) {
  PeekLoop();
  open(F,"$base/$fn");
  binmode(F);
  local $/="\015\012\015\012"; # get only headers
  my $h=<F>;
  undef $/;
  close F;
  my $a;
  if ($h=~/^From$HeaderSepRe($HeaderValueRe)/imo) {
   $a=$1; $a=~tr/\002\003//; # sanitize
   $a="$1 $2" if ($a=~/($EmailAdrRe)(\@$EmailDomainRe)/o);
   $a=decodeMimeWords($a);
   $a=encodeHTMLEntities(substr($a,0,40));
  }
  $c->[1]=$a; $a='';
  if ($h=~/^To$HeaderSepRe($HeaderValueRe)/imo) {
   $a=$1; $a=~tr/\002\003//; # sanitize
   if ($CanUseSRS && $EnableSRS) {
    my ($tt,$tt2);
    my $srs=new Mail::SRS(Secret=>$SRSSecretKey,
                          MaxAge=>$SRSTimestampMaxAge,
                          HashLength=>$SRSHashLength,
                          AlwaysRewrite=>1);
    my ($ac)=$a=~/^<?([^\015\012>]*).*/;
    if ($ac=~/SRS0[=+-].*/i) {
     if (eval{$tt=$srs->reverse($ac)}) {
      $a=~s/\Q$ac\E/$tt/;
     }
    } elsif ($ac=~/^SRS1[=+-].*/i) {
     if (eval{$tt=$srs->reverse($ac)} && eval{$tt2=$srs->reverse($tt)}) {
      $a=~s/\Q$ac\E/$tt2/;
     }
    }
   }
   $a="$1 $2" if ($a=~/($EmailAdrRe)(\@$EmailDomainRe)/o);
   $a=decodeMimeWords($a);
   $a=encodeHTMLEntities(substr($a,0,40));
  }
  $c->[2]=$a; $a='';
  if ($h=~/^Subject$HeaderSepRe($HeaderValueRe)/imo && $1=~/(\S.*)/s) {
   $a=$1; $a=~tr/\002\003//; # sanitize
   $a=decodeMimeWords($a);
   $a=encodeHTMLEntities(substr($a,0,60));
  } else {
   $a="&lt;no subject&gt;";
  }
  $c->[3]=$a;
  $c->[4]=0;
  $Corpus{$fn}=join("\003",@$c);
 }
 return $c;
}

sub corpusSetFlags {
 return unless $EnableCorpusInterface;
 my ($fn,$flags,$force)=@_;
 my $det=corpusDetails($fn,$force);
 return [undef] unless defined $det->[0];
 $det->[4]=$flags;
 $Corpus{$fn}=join("\003",@$det);
 return $det;
}

{
#################################################################
# this package implements a pure perl virus scanner
# it uses the clam anti-virus databases (see www.clamav.net)
# Download your databases this way -- maybe once a day:
#  wget --timestamping http://database.clamav.net/database/viruses.db
#  wget --timestamping http://database.clamav.net/database/viruses.db2
#
# copyright (C) 2004, John Hanna under the terms of the GPL

package Av;

use IO::File;

# load the databases -- return the number of signatures present
# optional parameters:
#   path => "/path/to/your/clamav/db/files", # default .
#   databases => "viruses.db,viruses.db2" # as many or as few as you want
sub init {
 my ($proto,$args)=@_;
 return sub{&main::jump;
  $path=$args->{path} || ".";
  $databases=$args->{databases} || "viruses.db,viruses.db2";
  return main::call('L1',loadAll()); L1:
 };
}

# public function to create a new scan buffer -- see addchar below
sub new {
 bless({offset=>0, buf=>'', prereq=>{}}, ref($_[0]) || $_[0]);
}

# public function to reset the scan buffer
sub clear {
 my $self=shift;
 $self->{offset}=0;
 $self->{buf}='';
 $self->{prereq}={};
}

# return the number of signatures in the virus database
sub count {
 $count;
}

# called internally, but can be called to manually reload the virus signature database
sub loadAll {
 my $self=shift;
 my (@fns,$i);
 return sub{&main::jump;
  $count=0;
  $longest=0;
  undef %prereqs;
  $prereqcount='a';
  undef @db;
  @fns=split(/,/,$databases);
  for ($i=0;$i<@fns;$i++) {
   return main::call('L1',load("$path/$fns[$i]")); L1:
  }
 };
}

# called internally to add a signature file to the database
sub load {
 my $fn=shift;
 my ($fh,$l,$nam,$sig,$lsig,@parts,$lp,$part,$p,$prereqn,$prereq,$return,$setprereq,$tail);
 my ($ltail,$hsize,$loc,$pretest,$rest,$lpretest,@pretest,$re,$match,$matchlen,$len);
 return sub{&main::jump;
  $fh=IO::File->new("<$fn");
  $fileTimes{$fn}=[stat($fh)]->[9];
  ($nam,$sig,$lsig)=();
  while ($l=<$fh>) {
   return main::cede('L1',8); L1:
   ($nam,$sig)=$l=~/(.*)=(.*)/;
   next unless $sig;
   $sig=lc $sig;
   $nam=~s/ \(clam\)//i;
   $nam=~s/'/\\'/g;
   @parts=split(/\*/,$sig);
   ($lp)=();
   foreach $part (0 .. $#parts) {
    $p=$parts[$part];
    $longest=length($p)/2 if (length($p)/2>$longest);
    $prereqn=$prereqs{$p} || ($prereqs{$p}=++$prereqcount);# if ($part<$#parts);
    $prereq=$part ? $prereqs{$lp} : '';
    $lp=$p;
    $return=$part==$#parts ? $nam:'';
    $setprereq=$part==$#parts ? '' : $prereqn;
    ($tail)=$p=~/([0-9a-f]{2,16})$/;
    $ltail=length($tail);
    $hsize=$ltail>=16 ? 8 : $ltail>=8 ? 4 : $ltail>=4 ? 2 : 1;
    $loc=substr($tail,-2*$hsize);
    ($pretest,$rest)=$p=~/([0-9a-f]{2,8})([0-9a-f\?]*)$/;
    $pretest=pack("H*",$pretest);
    $lpretest=length($pretest);
    $rest=length($rest)/2+$lpretest;
    (@pretest)=();
    if ($rest>$hsize && length($p)>32) {
     @pretest=(-$rest,$lpretest,$pretest);
    } else {@pretest=(0,0,'');}
    $test=$p;
    $test=~s/(..)/\\x$1/g;
    ($re,$match,$matchlen)=('','',0);
    if ($test=~s/\\x\?\?/./g) {
     $re=qr/$test$/s;
    } else {
     $len=length($p)/2;
     $matchlen=$len; $match=pack("H*",$p);
     #$match="" if $len==$hsize;
    }
    push(@{$db[$hsize]->{pack("H*",$loc)}}, [$prereq,$return,$setprereq,@pretest,$re,$match,$matchlen]);
   }
   $count++;
  }
  close $fh;
 };
}

# public function to check if the database needs to be reloaded
# use this this way: Av->loadAll if Av->checkReload;
sub checkReload {
 foreach my $fn (split(/,/,$databases)) {
  $fn="$path/$fn";
  # we want to reload if a file is newer (has later date) than when read,
  # and is at least 120 seconds old -- in lieu of locking
  my $mtime=[stat($fn)]->[9];
  return 1 if $mtime>$fileTimes{$fn} && time-$mtime>120;  
 }
 return 0;
}

# public function to scan a file
# returns undef if no virus found
# returns array-ref with the offset into the buffer and the name of the virus if found
# you can pass in an offset to start scanning to continue scanning the file
# you may need to $av->clear to get the desired effects
sub scanfile {
 my ($self,$fn,$n)=@_;
 my $fh=IO::File->new("<$fn") or die("Couldn't open $fn: $!");
 binmode $fh; # fixme: Perl5.6 IO::File lacks binmode support
 my $c;
 $self->{offset}=$n;
 $self->{buf}='';
 $self->{prereq}={};
 seek($fh,$n,0) if $n>0;
 seek($fh,$n,2) if $n<0;
 my $r;
 while (defined($c=getc($fh))) {
  return $r if $r=$self->addchar($c);
 }
 close $fh;
 return undef;
}

# public function to do character-at-a-time scanning.
# $av=Av->new();
# foreach my $c (split(//,$buf)) {
#  print "'$r->[1]' virus found at offset $r->[0]\n" if $r=$av->addchar($c);
# }
sub addchar {
 my $self=shift;
 $self->{buf}.=$_[0];
 $self->{offset}++;
 if (length($self->{buf})>$longest*2) {
  $self->{buf}=substr($self->{buf}, -$longest);
 }
 foreach $hsiz (8,4,2,1) {
  my $l=$db[$hsiz]->{substr($self->{buf},-$hsiz)};
  foreach (@{$l}){
   if (!$_->[0] || $self->{prereq}->{$_->[0]}) {
    # pre test
    if (!$_->[4] || substr($self->{buf},$_->[3],$_->[4]) eq $_->[5]) {
     # real test
     if ($_->[8] && substr($self->{buf},-$_->[8]) eq $_->[7] || !$_->[8] && $self->{buf}=~$_->[6]) {
      $_->[2] && ($self->{prereq}->{$_->[2]}=1) or return [$self->{offset},$_->[1]];
     }
    }
   }
  }
 }
 return undef;
}

}

{
#################################################################
# this package implements realtime blacklisting
# it is based on Net::RBLClient by Asher Blum <asher@wildspark.com>
# CREDITS Martin H. Sluka <martin@sluka.de>
# Copyright (C) 2002 Asher Blum.  All rights reserved.
# This code is free software; you can redistribute it and/or modify it under
# the same terms as Perl itself.
# Modified for integration with ASSP by John Calvi and Przemek Czerkas

package RBL;

use IO::Socket;

sub new {
 # This avoids compile time errors if Net::DNS is not installed.
 # The error will be returned on the lookup function call.
 if ($main::CanUseDNS) {
  require Net::DNS::Packet;
  $CanUseDNS=1;
 }
 my ($class, %args)=@_;
 my $self={lists       => [ lists() ],
           query_txt   => 1,
           max_time    => 10,
           timeout     => 1,
           max_hits    => 3,
           max_replies => 6,
           udp_maxlen  => 4000,
           server      => '127.0.0.1'};
 bless $self, $class;
 foreach my $key(keys %args) {
  defined($self->{$key}) or return "Invalid key: $key";
  $self->{$key}=$args{$key};
 }
 $self;
}

sub lookup {
 my ($self,$fh,$target)=@_;
 my ($deadline,$sock,$i,$j,%times,$list,$msg_a,$msg_t,$msg,$needed,$hits,$replies,$time,$domain,$res,$type);
 return sub{&main::jump;
  return unless $CanUseDNS;
  $target=join '.', reverse(split /\./, $target) if $target=~/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
  $sock=IO::Socket::INET->new(Proto     => 'udp',
                              PeerPort  => 53,
                              PeerAddr  => $self->{server});
  unless ($sock) {
   main::mlog(0,"Failed to create UDP client");
   return;
  }
  # Fisher-Yates shuffle
  $i=@{$self->{lists}};
  if ($i) {
   while (--$i) {
    $j=int rand($i+1);
    @{$self->{lists}}[$i,$j]=@{$self->{lists}}[$j,$i];
   }
  }
  %times={};
  if ($self->{query_txt}) {
   foreach $list(@{$self->{lists}}) {
    ($msg_a, $msg_t)=mk_packet($target, $list);
    foreach ($msg_a, $msg_t) {
     unless ($sock->send($_)) {
      main::mlog(0,"RBL lookup send: $!");
      close($sock);
      return;
     }
    }
    $times{$list}=Time::HiRes::time() if $main::AvailHiRes;
   }
  } else {
   foreach $list(@{$self->{lists}}) {
    $msg=mk_packet($target, $list);
    unless ($sock->send($msg)) {
     main::mlog(0,"RBL lookup send: $!");
     close($sock);
     return;
    }
    $times{$list}=Time::HiRes::time() if $main::AvailHiRes;
   }
  }
  $self->{results}={};
  $self->{txt}={};
  if ($self->{max_replies}>@{$self->{lists}}) {
   $needed=@{$self->{lists}};
  } else {
   $needed=$self->{max_replies};
  }
  $needed <<= 1 if $self->{query_txt}; # how many packets needed back
  $hits=$replies=0;
  $deadline=time+$self->{max_time};
  # Keep receiving packets until one of the exit conditions is met:
  main::mlogCond($fh,"Commencing RBL checks on $target",$main::RBLLog);
  while ($needed && time<$deadline) {
   main::waitTaskRead(0,$sock,$self->{timeout});
   return main::cede('L1'); L1:
   next unless main::getTaskWaitResult(0);
   unless ($sock->recv($msg, $self->{udp_maxlen})) {
    main::mlog(0,"RBL lookup recv: $!");
    close($sock);
    return;
   }
   if ($msg) {
    ($domain, $res, $type)=decode_packet($fh,$msg,$target);
    if (defined $type && $type eq 'TXT') {
     $self->{txt}{$domain}=$res
    } else {
     if ($res) {
      $hits ++;
      $self->{results}{$domain}=$res;
      $main::Stats{"providerHits$domain"}++;
     }
     $replies ++;
     $main::Stats{"providerReplies$domain"}++;
     if ($main::AvailHiRes) {
      $time=Time::HiRes::time()-$times{$domain};
      $main::Stats{"providerTime$domain"}+=$time;
      $main::Stats{"providerMinTime$domain"}=$time if $time<$main::Stats{"providerMinTime$domain"} || !$main::Stats{"providerMinTime$domain"};
      $main::Stats{"providerMaxTime$domain"}=$time if $time>$main::Stats{"providerMaxTime$domain"};
     }
     last if $hits>=$self->{max_hits} || $replies>=$self->{max_replies};
    }
    $needed --;
   }
  }
  main::mlogCond($fh,"Completed RBL checks on $target",$main::RBLLog);
  close ($sock);
  return;
 };
}

sub listed_by {
 my $self=shift;
 sort keys %{$self->{results}};
}

sub listed_hash {
 my $self=shift;
 %{$self->{results}};
}

sub txt_hash {
 my $self=shift;
 warn <<EOT unless $self->{query_txt};
Without query_txt turned on, you won't get any results from ->txt_hash().
EOT
 if (wantarray) { %{$self->{txt}} }
 else { $self->{txt} }
}

# End methods - begin internal functions

sub mk_packet {
 # pass me a target and a blocklist domain
 my ($target, $list)=@_;
 my ($packet, $error)=new Net::DNS::Packet(my $fqdn="$target.$list", 'A');
 unless ($packet) {
  main::mlog(0,"Cannot build DNS query for $fqdn, type A: $error");
  return;
 }
 return $packet->data unless wantarray;
 my ($txt_packet, $error)=new Net::DNS::Packet($fqdn, 'TXT', 'IN');
 unless ($txt_packet) {
  main::mlog(0,"Cannot build DNS query for $fqdn, type TXT: $error");
  return;
 }
 $packet->data, $txt_packet->data;
}

sub decode_packet {
 # takes a raw DNS response packet
 # returns domain, response
 my ($fh,$data,$target)=@_;
 my $packet=Net::DNS::Packet->new(\$data);
 my @answer=$packet->answer;
 {
  my ($res, $domain, $type);
  foreach my $answer (@answer) {
   {
    # removed $answer->answerfrom because it caused an error
    # with some types of answers

    my $name=lc $answer->name;
    main::mlogCond($fh,"Packet contained answers to different domains ($domain != $name)",$main::RBLLog)
     if defined $domain && $name ne $domain;
    $domain=$name;
   }
   $domain=~s/\Q$target\E\.//;
   $type=$answer->type;
   $res=$type eq 'A'     ? inet_ntoa($answer->rdata) :
        $type eq 'CNAME' ? cleanup($answer->rdata) :
        $type eq 'TXT'   ? (defined $res && "$res; ").$answer->txtdata :
                           '?';
   last unless $type eq 'TXT';
  }
  return $domain, $res, $type if defined $res;
 }
 # OK, there were no answers -
 # need to determine which domain
 # sent the packet.
 my @question=$packet->question;
 foreach my $question(@question) {
  my $domain=$question->qname;
  $domain=~s/\Q$target\E\.//;
  return($domain, undef);
 }
}

sub cleanup {
 # remove control chars and stuff
 $_[0]=~tr/a-zA-Z0-9./ /cs;
 $_[0];
}


sub lists {
 qw(bl.spamcop.net
    cbl.abuseat.org
    sbl-xbl.spamhaus.org
    dnsbl.njabl.org
    list.dsbl.org
    dnsbl.sorbs.net
    opm.blitzed.org
    dynablock.njabl.org);
}

}