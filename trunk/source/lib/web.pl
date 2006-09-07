#!/usr/bin/perl

# perl antispam smtp proxy
# (c) John Hanna, John Calvi, Robert Orso, AJ 2004 under the terms of the GPL
# (c) 2006 Przemyslaw Czerkas <przemekc@poczta.onet.pl>

$version='1.2.0';
$modversion=' beta 0';

use bytes; # get rid of annoying 'Malformed UTF-8' messages

%WebRequests=('/lists' => \&webLists,
              '/analyze' => \&webAnalyze,
              '/simulate' => \&webSimulate,
              '/logs' => \&webLogs,
              '/corpus' => \&webCorpus,
              '/view' => \&webView,
              '/stats' => \&webStats,
              '/shutdown' => \&webShutdown,
              '/shutdown_frame' => \&webShutdownFrame,
              '/docs' => \&webDocs,
              '/donations' => \&webDonations,
              '/edit' => \&webEdit,
              '/get' => \&webGetFile,
              '/tooltip' => \&webTooltip);

@Highlights=('<span style="color:black; background-color:#ffff66">',
             '<span style="color:black; background-color:#A0FFFF">',
             '<span style="color:black; background-color:#99ff99">',
             '<span style="color:black; background-color:#ff9999">',
             '<span style="color:black; background-color:#ff66ff">',
             '<span style="color:white; background-color:#880000">',
             '<span style="color:white; background-color:#00aa00">',
             '<span style="color:white; background-color:#886800">',
             '<span style="color:white; background-color:#004699">',
             '<span style="color:white; background-color:#990099">');

@News=('smtpAuthServer','SMTPreadtimeout','localHostNames','GreetDelay','GreetDelay2','noGreetDelay','GreetDelayError',
       'ValidateHelo','HeloPosition','HeloExtra','HeloForged','HeloMismatch','hlSpamRe','noHelo','ValidateSender',
       'SenderPosition','SenderExtra','SenderForged','SenderLDAP','SenderMX','noSenderCheck',
       'DetectInvalidRecipient','LDAPHost','npLwlRe','mfSpamLovers','delayingSpamLovers','msgVerifySpamLovers',
       'bombsSpamLovers','uriblSpamLovers','ratelimitSpamLovers','spamSubjectSL','SPFPosition','SPFExtra','noSPF','SPFError',
       'ValidateRWL','AddRWLHeader','RWLServiceProvider','RWLmaxreplies','RWLminhits','RWLmaxtime','noRWL',
       'RBLPosition','RBLExtra','RBLServiceProvider','noRBL','RBLError','noSRS','SRSRewriteToHeader','SRSBounceError',
       'EnableMsgVerify','MsgVerifyExtra','MsgVerifyHeaders','MsgVerifyLineLength','noMsgVerify','noBombScript',
       'noAttachment','ValidateURIBL','URIBLExtra','AddURIBLHeader','URIBLServiceProvider','URIBLCCTLDS',
       'URIBLmaxuris','URIBLmaxdomains','URIBLNoObfuscated','URIBLmaxreplies','URIBLmaxhits','URIBLmaxtime',
       'URIBLsocktime','URIBLwhitelist','noURIBL','URIBLPolicyError','URIBLError','AvUseClamAV','AvDestination','Avmaxtime',
       'AddSpamAnalysisHeader','mfTestMode','malformedTestMode','uriblTestMode','ccHam','ccSpam','ccBlocked','ccHamSubject',
       'ccSpamSubject','ccBlockedSubject','ccFilter','EnableRateLimit','RateLimitPosition','RateLimitExtra',
       'RateLimitUseNetblocks','RateLimitClient','RLIBTclientHeloValidated','RLIBTclientHeloUnchecked',
       'RLIBTclientHeloForged','RLIBTclientHeloBlacklisted','RLIBTclientHeloMismatch','RLIBTclientHeloSpam','RateLimitSender',
       'RLIBTsenderValidatedLocal','RLIBTsenderUncheckedLocal','RLIBTsenderWhitelisted','RLIBTsenderValidatedRemote',
       'RLIBTsenderUncheckedRemote','RLIBTsenderUnprocessed','RLIBTsenderForged','RLIBTsenderInvalidLocal',
       'RLIBTsenderNoMX','RLIBTsenderInvalidRemote','RateLimitRcpt','RLIBTrcptValidated','RLIBTrcptUnchecked',
       'RLIBTrcptSpamLover','RLIBTrcptWhitelisted','RLIBTrcptNotWhitelisted','RLIBTrcptUnprocessed',
       'RLIBTrcptDelayed','RLIBTrcptDelayedLate','RLIBTrcptDelayedExpired','RLIBTrcptEmbargoed',
       'RLIBTrcptSpamBucket','RateLimitPassed','RLIBTmsgAnyHam','RLIBTnoprocessing','RLIBTlocals','RLIBTwhites',
       'RLIBTreds','RLIBTbhams','RLIBTmsgAnyPassedSpam','RLIBTspamlover','RLIBTtestspams','RateLimitBlocked',
       'RLIBTmsgAnyBlockedSpam','RLIBThelolisted','RLIBTsenderfails','RLIBTblacklisted','RLIBTmsgNoSRSBounce',
       'RLIBTspambucket','RLIBTspffails','RLIBTrblfails','RLIBTmalformed','RLIBTuriblfails','RLIBTbombs',
       'RLIBTscripts','RLIBTviri','RLIBTviridetected','RLIBTbspams','RateLimitEmailInterface','RLIBTrcptReportSpam',
       'RLIBTrcptReportHam','RLIBTrcptReportWhitelistAdd','RLIBTrcptReportWhitelistRemove','RLIBTrcptReportRedlistAdd',
       'RLIBTrcptReportRedlistRemove','RateLimitMisc','RLIBTrcptNonexistent','RLIBTmsgNoRcpt','RLIBTrcptRelayRejected',
       'RLIBTmsgMaxErrors','RLIBTmsgEarlytalker','RLIBTmsgDelayed','RLIBTmsgAborted','noRateLimit','RateLimitError',
       'RateLimitBlockedError','npColl','localColl','whiteColl','redColl','baysNonSpamColl','baysSpamColl',
       'spamHeloColl','mfFailColl','blDomainColl','SRSFailColl','spamBucketColl','SPFFailColl','RBLFailColl',
       'malformedColl','URIBLFailColl','spamBombColl','scriptColl','wlAttachColl','npAttachColl','extAttachColl',
       'viriColl','FilesDistribution','NoHaikuCorrection','NoHaikuWhitelist','NoHaikuRedlist','ratelimitdb','corpusdb',
       'slogfile','ClientValLog','SenderValLog','RecipientValLog','AvLog','RELog','IPMatchLog','RateLimitLog',
       'EmailInterfaceLog','AdminConnectionLog','ServerSessionLog','LogRollDays','LogRotateCopies','MaxRebuildBytes',
       'IncomingBufSize','MaintenanceInterval','EnableCorpusInterface','MaillogContextLines','BackupCopies','webAdminCharset',
       'DetailedStats','ShowTooltipsIP','ShowTooltipsHost','ShowTooltipsEmail','ShowNews');

@StatsMsgItems=([0,'Noprocessing Messages:','positive','noprocessing'],
                [0,'Local Messages:','positive','locals'],
                [0,'Whitelisted Messages:','positive','whites'],
                [0,'Redlisted Messages:','positive','reds'],
                [0,'Bayesian Hams:','positive','bhams'],
                [0,'Spamlover Spams:','positive','spamlover'],
                [0,'Testmode Spams:','positive','testspams'],
                [0,'Email Reports:','positive','reports'],
                [0,'Bayesian Spams:','negative','bspams'],
                [0,'Earlytalkers Rejected:','negative','msgEarlytalker'],
                [0,'Invalid HELO Messages:','negative','helolisted'],
                [0,'Invalid Sender Messages:','negative','senderfails'],
                [0,'Blacklisted Domain Messages:','negative','blacklisted'],
                [0,'Empty Recipient Messages:','negative','msgNoRcpt'],
                [0,'Delayed Messages:','negative','msgDelayed'],
                [0,'Not SRS Signed Bounces:','negative','msgNoSRSBounce'],
                [0,'Spam Trap Address Messages:','negative','spambucket'],
                [0,'SPF Failures:','negative','spffails'],
                [0,'RBL Failures:','negative','rblfails'],
                [0,'Malformed Messages:','negative','malformed'],
                [0,'URIBL Failures:','negative','uriblfails'],
                [0,'Spam Bombs Blocked:','negative','bombs'],
                [0,'Scripts Blocked:','negative','scripts'],
                [0,'Attachments Blocked:','negative','viri'],
                [0,'Viruses Detected:','negative','viridetected'],
                [0,'Max Errors Exceeded:','negative','msgMaxErrors'],
                [0,'Rate Limit Exceeded:','negative','msgRateLimited'],
                [0,'Aborted Messages:','negative','msgAborted']);

@StatsTrafItems=([0,'Client Bytes Accepted:','positive','rbytesClientAccepted'],
                 [1,'Noprocessing Messages:','positive','rbytesnoprocessing'],
                 [1,'Local Messages:','positive','rbyteslocals'],
                 [1,'Whitelisted Messages:','positive','rbyteswhites'],
                 [1,'Redlisted Messages:','positive','rbytesreds'],
                 [1,'Bayesian Hams:','positive','rbytesbhams'],
                 [1,'Spamlover Spams:','positive','rbytesspamlover'],
                 [1,'Testmode Spams:','positive','rbytestestspams'],
                 [1,'Email Reports:','positive','rbytesreports'],
                 [1,'Other Traffic:','positive','rbytesother'],
                 [0,'Server Bytes Passed:','positive','wbytesServerPassed'],
                 [1,'Proxied Traffic:','positive','wbytesproxied'],
                 [1,'CC Messages:','positive','wbytescc'],
                 [1,'Email Report Returns:','positive','wbytesreportreturns'],
                 [0,'Client Bytes Blocked:','negative','rbytesClientBlocked'],
                 [1,'Bayesian Spams:','negative','rbytesbspams'],
                 [1,'Earlytalkers Rejected:','negative','rbytesmsgEarlytalker'],
                 [1,'Invalid HELO Messages:','negative','rbyteshelolisted'],
                 [1,'Invalid Sender Messages:','negative','rbytessenderfails'],
                 [1,'Blacklisted Domain Messages:','negative','rbytesblacklisted'],
                 [1,'Empty Recipient Messages:','negative','rbytesmsgNoRcpt'],
                 [1,'Delayed Messages:','negative','rbytesmsgDelayed'],
                 [1,'Not SRS Signed Bounces:','negative','rbytesmsgNoSRSBounce'],
                 [1,'Spam Trap Address Messages:','negative','rbytesspambucket'],
                 [1,'SPF Failures:','negative','rbytesspffails'],
                 [1,'RBL Failures:','negative','rbytesrblfails'],
                 [1,'Malformed Messages:','negative','rbytesmalformed'],
                 [1,'URIBL Failures:','negative','rbytesuriblfails'],
                 [1,'Spam Bombs Blocked:','negative','rbytesbombs'],
                 [1,'Scripts Blocked:','negative','rbytesscripts'],
                 [1,'Attachments Blocked:','negative','rbytesviri'],
                 [1,'Viruses Detected:','negative','rbytesviridetected'],
                 [1,'Max Errors Exceeded:','negative','rbytesmsgMaxErrors'],
                 [1,'Rate Limit Exceeded:','negative','rbytesmsgRateLimited'],
                 [1,'Aborted Messages:','negative','rbytesmsgAborted'],
                 [1,'Other Traffic:','negative','rbytesotherblocked'],
                 [0,'Server Bytes Aborted:','negative','wbytesServerAborted']);

#####################################################################################
#                HTTP Socket handlers

sub taskNewWebConnection {
 my ($ip,$port);
 return coro(sub{&jump;
  while ($WebSocket->opened()) {
   waitTaskRead(0,$WebSocket,7);
   return cede('L1'); L1:
   next unless getTaskWaitResult(0);
   next unless my $client=$WebSocket->accept();
   binmode($client);
   $ip=$client->peerhost();
   $port=$client->peerport();
   if ($allowAdminConnections && !matchIP($ip,'allowAdminConnections')) {
    mlog(0,"admin connection from $ip:$port rejected by allowAdminConnections") unless $noLog && $ip=~$NLOGRE;
    $client->close();
    $Stats{admConnDenied}++;
    next;
   }
   # logging is done later (in webRequest()) due to /shutdown_frame page, which auto-refreshes
   $Con{$client}->{itid}=newTask(taskWebTraffic($client),'NORM',0,'W');
  }
 });
}

sub taskWebTraffic {
 my $fh=shift;
 my ($this,$buf,$resp,$resph,$respb,$time,$enc,$deflater);
 return coro(sub{&jump;
  $this=$Con{$fh};
  while ($fh->opened()) {
   waitTaskRead(0,$fh,7);
   return cede('L1'); L1:
   next unless getTaskWaitResult(0);
   ($buf)=();
   last unless $fh->sysread($buf,4096)>0; # connection closed by peer
   $this->{reqbuf}.=$buf;
   # throw away connections longer than 1M to prevent flooding
   if (length($this->{reqbuf})>1030000) {
    $fh->close();
    last;
   }
   ($resp)=();
   $this->{reqblen}=$1 if !$this->{reqblen} && $this->{reqbuf}=~/Content-length: (\d+)/i; # POST request?
   if ($this->{reqbuf}=~/^(.*?\015\012)\015\012(.*)/s && length($2)>=$this->{reqblen}) {
    return call('L2',webRequest($fh,$1,$2)); L2:
    $resp=shift;
   }
   if ($resp=~/^(.*?\n)\n(.*)/s) {
    ($resph,$respb)=($1,$2);
    $time=gmtime();
    $time=~s/(...) (...) +(\d+) (........) (....)/$1, $3 $2 $5 $4 GMT/;
    $resph.="Server: ASSP/$version$modversion\n";
    $resph.="Date: $time\n";
    if ($EnableHTTPCompression && $CanUseHTTPCompression) {
     if ($this->{reqbuf}=~/Accept-Encoding: (.*?)\015\012/i && $1=~/(gzip|deflate)/i) {
      $enc=$1;
      if ($enc=~/gzip/i) {
       # encode with gzip
       $respb=Compress::Zlib::memGzip($respb);
      } else {
       # encode with deflate
       $deflater=deflateInit();
       $respb=$deflater->deflate($respb);
       $respb.=$deflater->flush();
      }
      $resph.="Content-Encoding: $enc\n";
     }
    }
    $resph.='Content-Length: '.length($respb)."\n";
    $resph=~s/\n/\015\012/g;
    print $fh "$resph\015\012$respb";
    # close connection
    $fh->close();
    last;
   }
  }
  delete $Con{$fh};
 });
}

#####################################################################################
#                helper functions

sub encodeHTMLEntities {
 my $s=shift;
 $s=~s/&/&amp;/gs;
 $s=~s/</&lt;/gs;
 $s=~s/>/&gt;/gs;
 $s=~s/"/&quot;/gs;
 return $s;
}

sub decodeHTMLEntities {
 my $s=shift;
 $s=~s/&quot;?/"/gis;
 $s=~s/&gt;?/>/gis;
 $s=~s/&lt;?/</gis;
 $s=~s/&amp;?/&/gis;
 return $s;
}

# escape query string
sub escapeQuery {
 my $s=shift;
 $s=~s/([^\w\-!~*() ])/sprintf("%%%02X",ord($1))/ge;
 $s=~tr/ /+/;
 return $s;
}

sub HTTPStrToTime {
 my $str=shift;
 if ($str=~/[SMTWF][a-z][a-z], (\d\d) ([JFMAJSOND][a-z][a-z]) (\d\d\d\d) (\d\d):(\d\d):(\d\d) GMT/) {
  my %MoY=qw(Jan 1 Feb 2 Mar 3 Apr 4 May 5 Jun 6 Jul 7 Aug 8 Sep 9 Oct 10 Nov 11 Dec 12);
  return eval{
   my $t=Time::Local::timegm($6, $5, $4, $1, $MoY{$2}-1, $3-1900);
   $t<0 ? undef : $t
  };
 } else {
  return undef;
 }
}

# add tooltip span tags (in place)
sub addTooltips {
 my $class;
 $class='tooltip_elem' unless $_[1];
 if ($ShowTooltipsEmail) {
  # handle email addresses
  $_[0]=~s/($EmailAdrRe\@$EmailDomainRe)/<span class="$class" _class="$class" _class_active="tooltip_email" _param="1" onMouseOver="initTooltip(this);" onClick="selectElement(this);">$1<\/span>/g;
 }
 if ($ShowTooltipsIP) {
  # handle IP addresses
  $_[0]=~s/((?<![@.\w\-])\b(?:\d{1,3}\.){3}\d{1,3}\b(?![@.\w\-]))/<span class="$class" _class="$class" _class_active="tooltip_ip" _param="2" onMouseOver="initTooltip(this);" onClick="selectElement(this);">$1<\/span>/g;
 }
 if ($ShowTooltipsHost) {
  # handle host names
  $_[0]=~s/((?<![@.\w\-])\b(?:[\w\-]+\.)+[a-z]{2,5}\b(?![@.\w\-]))/<span class="$class" _class="$class" _class_active="tooltip_host" _param="3" onMouseOver="initTooltip(this);" onClick="selectElement(this);">$1<\/span>/gi;
 }
}

sub checkUpdate {
 my ($name,$default,$valid,$onchange,$http,$gpc)=@_;
 return '' unless exists $gpc->{theButton};
 $gpc->{$name}=$default if $gpc->{$name} eq '?';
 if ($gpc->{$name} ne $Config{$name}) {
  if ($gpc->{$name}=~/^$valid$/i) {
   my $new=$1; my $info;
   my $old=$Config{$name};
   $Config{$name}=$new;
   if ($onchange) {
    $info=$onchange->($name,$old,$new);
   } else {
    mlog(0,"admin update: $name changed from '$old' to '$new'");
    # -- this sets the variable name with the same name as the config key to the new value
    # -- for example $Config{myName}='ASSP-nospam' -> $myName='ASSP-nospam';
    ${$name}=$new;
   }
   $ConfigChanged{$name}=1;
   return "<span class=\"positive\"><b>*** Updated $info</b></span><br />";
  } else {
   return "<span class=\"negative\"><b>*** Invalid: '$gpc->{$name}'</b></span><br />";
  }
 }
}

#####################################################################################
#                Web Configuration functions

sub webRequest {
 my ($fh,$reqh,$reqb);
 my ($i,%_http,$http,$page,$query,%get,$q,$k,$v,%post,$r);
 my ($user,$pass,$ip,$port,$args,%cookie,$c,%_gpc,$gpc,$auth);
 my $sref=$Tasks{$CurTaskID}->{webRequest}||=[sub{
  ($fh,$reqh,$reqb)=@_;
 },sub{&jump;
  # parse http request headers
  $i=0;
  (%_http)=map{++$i % 2 ? lc $_ : $_} map/^([^: ]*)[: ]{0,2}(.*)/, split(/\015\012/,$reqh);
  $http=\%_http;
  ($page,$query)=($http->{get} || $http->{head} || $http->{post})=~/^([^\? ]+)(?:\?(\S*))?/;
  # parse query string (GET)
  (%get)=();
  foreach $q (split('&',$query)) {
   ($k,$v)=split('=',$q);
   $k=~tr/+/ /;
   $k=~s/%([0-9a-fA-F]{2})/pack('C',hex($1))/ge;
   $k=~s/(e)_(mail)/$1$2/gi; # get rid of google autofill
   $v=~tr/+/ /;
   $v=~s/%([0-9a-fA-F]{2})/pack('C',hex($1))/ge;
   if ($k=~/\[\]$/) {
    push(@{$get{$k}},$v);
   } else {
    $get{$k}=$v;
   }
  }
  # parse request body (POST)
  (%post)=();
  if ($reqb) {
   if ($http->{'content-type'}=~/application\/x-www-form-urlencoded/i) {
    $reqb=~s/\015?\012|\015//; # strip out extra CR's and/or LF's
    foreach $r (split('&',$reqb)) {
     ($k,$v)=split('=',$r);
     $k=~tr/+/ /;
     $k=~s/%([0-9a-fA-F]{2})/pack('C',hex($1))/ge;
     $k=~s/(e)_(mail)/$1$2/gi; # get rid of google autofill
     $v=~tr/+/ /;
     $v=~s/%([0-9a-fA-F]{2})/pack('C',hex($1))/ge;
     if ($k=~/\[\]$/) {
      push(@{$post{$k}},$v);
     } else {
      $post{$k}=$v;
     }
    }
   } else {
    # multipart/form-data uploads are not handled yet
    return <<EOT;
HTTP/1.0 400 Bad Request
Content-type: text/html

<html>
<body>
  <h1>Bad request</h1>
</body>
</html>
EOT
   }
  }
  # parse cookie string (COOKIE)
  (%cookie)=();
  foreach $c (split(/; ?/,$http->{cookie})) {
   ($k,$v)=$c=~/^([^= ]*)[= ]{0,2}(.*)/;
   $k=~s/%([0-9a-fA-F]{2})/pack('C',hex($1))/ge;
   $v=~s/%([0-9a-fA-F]{2})/pack('C',hex($1))/ge;
   $cookie{$k}=$v;
  }
  # GPC variables order
  %_gpc=(%get,%post,%cookie);
  $gpc=\%_gpc;
  ($auth)=$http->{authorization}=~/Basic (\S+)/i;
  ($user,$pass)=split(':',base64decode($auth));
  $ip=$fh->peerhost();
  $port=$fh->peerport();
  if (!$webAdminPassword || $pass eq $webAdminPassword) {
   if ($page!~/shutdown_frame|favicon.ico|get/i) {
    # only count requests for pages without meta refresh tag
    # dont count requests for favicon.ico file
    # dont count requests for 'get' page
    ($args)=();
    if ($page=~/edit/i) {
     if ($gpc->{B1}=~/delete/i) {
      $args='; deleting';
     } elsif (defined($gpc->{contents})) {
      $args='; writing';
     } else {
      $args='; reading';
     }
     $args.=" file:$gpc->{file}";
    }
    mlog(0,"admin connection from $ip:$port; page:$page$args") if $AdminConnectionLog;
    $Stats{admConn}++;
   }
   webQuit() if $page=~/quit/i;
   if ($page=~/favicon.ico/i) {
    return <<EOT;
HTTP/1.0 404 Not Found
Content-type: text/html

<html>
<body>
  <h1>Not found</h1>
</body>
</html>
EOT
   } else {
    return call('L1',defined($v=$WebRequests{$page}) ? $v->($http,$gpc) : webConfig($http,$gpc)); L1:
    return shift;
   }
  } else {
   if ($pass ne '') {
    mlog(0,"admin connection from $ip:$port; page:$page rejected -- authorization failed") unless $noLog && $ip=~$NLOGRE;
    $Stats{admConnDenied}++;
   }
   return <<EOT;
HTTP/1.0 401 Unauthorized
WWW-Authenticate: Basic realm="Anti-Spam SMTP Proxy (ASSP) Configuration"
Content-type: text/html

<html>
<body>
  <h1>Unauthorized</h1>
</body>
</html>
EOT
  }
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub webRender {
 $HTTPHeaderOK='HTTP/1.0 200 OK
Content-type: text/html
Pragma: no-cache';
 $HTMLHeaderDTDStrict='
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">';
 $HTMLHeaderDTDTransitional='
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">';
 my $JavaScript=<<EOT;
  <script type=\"text/javascript\" src=\"get?file=images/assp.js\"></script>
EOT
 if ($EnableFloatingMenu) {
  $JavaScript.=<<EOT;
  <script type=\"text/javascript\" src=\"get?file=images/float.js\"></script>
EOT
 }
 if ($ShowTooltipsIP || $ShowTooltipsHost || $ShowTooltipsEmail) {
  $JavaScript.=<<EOT;
  <script type=\"text/javascript\" src=\"get?file=images/rslite.js\"></script>
  <script type=\"text/javascript\" src=\"get?file=images/tooltip.js\"></script>
EOT
 }
 chomp($JavaScript);
 $HTMLHeaders=<<EOT;
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
<head>
  <meta http-equiv="content-type" content="application/xhtml+xml; charset=$webAdminCharset" />
  <title>ASSP (Anti SPAM SMTP Proxy)</title>
  <link rel="stylesheet" href="get?file=images/assp.css" type="text/css" />
  <link rel="stylesheet" href="get?file=images/tooltip.css" type="text/css" />
  <link rel="shortcut icon" href="get?file=images/favicon.ico" />
$JavaScript
</head>
<body>
  <p>
    <a href="http://assp.sourceforge.net/"><img src="get?file=images/logo.jpg" alt="ASSP" /></a>
  </p>
  <div class="navMenu"
EOT
 chomp($HTMLHeaders);
 $HTMLHeaders.=' id="navMenu" style="position:absolute"' if $EnableFloatingMenu;
 $HTMLHeaders.=">\n";
 $HTMLHeaders.=<<EOT;
    <div>
      <div style="text-align: center;">
        <a onmousedown="expand(1, 1)">Expand All</a>&nbsp;&nbsp;&nbsp;<a onmousedown="expand(0, 1)">Collapse All</a>
      </div>
      <hr />
      <div class="menuLevel1">
        <a href="/"><img src="get?file=images/plusIcon.png" alt="plusicon" /> Main</a><br />
      </div>
EOT
 my $counter=0;
 foreach my $c (@Config) {
  if (@{$c}==5) {
   $HTMLHeaders.=<<EOT;
    </div>
    <div class="menuLevel2"><a onmousedown="toggleDisp('$counter')"><img id="treeIcon$counter" src="get?file=images/plusIcon.png" alt="plusicon" /> $c->[4]</a></div>
    <div id="treeElement$counter" style="padding-left: 3px; display: block">
EOT
   $counter++;
  } else {
   $HTMLHeaders.=<<EOT;
      <div class="menuLevel3"><a href="/#$c->[0]">$c->[0]</a></div>
EOT
  }
 }
 $HTMLHeaders.=<<EOT;
    </div>
    <div class="menuLevel1">
      <a href="analyze"><img src="get?file=images/noIcon.png" alt="noicon" /> <b>Analyzer</b></a><br />
      <a href="simulate"><img src="get?file=images/noIcon.png" alt="noicon" /> <b>Simulator</b></a><br />
      <a href="lists"><img src="get?file=images/noIcon.png" alt="noicon" /> <b>Lists</b></a><br />
      <a href="logs"><img src="get?file=images/noIcon.png" alt="noicon" /> <b>Maillogs</b></a><br />
      <a href="corpus"><img src="get?file=images/noIcon.png" alt="noicon" /> <b>Corpus</b></a><br />
      <a href="stats"><img src="get?file=images/noIcon.png" alt="noicon" /> <b>Statistics</b></a><br />
      <a href="shutdown"><img src="get?file=images/noIcon.png" alt="noicon" /> <b>Shutdown</b></a><br />
      <a href="docs"><img src="get?file=images/noIcon.png" alt="noicon" /> <b>Documentation</b></a><br />
      <a href="donations"><img src="get?file=images/noIcon.png" alt="noicon" /> <b>Donations</b></a><br />
    </div>
    <hr />
    <div style="text-align: center;">
      <a href="http://assp.sourceforge.net">ASSP</a> v$version$modversion<br />
    </div>
  </div>
  <script type="text/javascript">
  <!--
EOT
 $HTMLHeaders.="    JSFX_FloatDiv('navMenu',2,50,2,-2,2,99999).flt();\n" if $EnableFloatingMenu;
 $HTMLHeaders.=<<EOT;
    expand(0,0);
  // -->
  </script>
EOT
 $HTMLHeaders.="  <div class=\"tooltip_pop\" id=\"tooltip_pop\" onMouseOver=\"selectElement(this)\" onClick=\"selectElement(this);\"></div>\n" if $ShowTooltipsIP || $ShowTooltipsHost || $ShowTooltipsEmail;
 chomp($HTMLHeaders);
 $HTMLFooters=<<EOT;
  <div class="content">
    <a href="http://sourceforge.net" rel="external"><img src="http://sourceforge.net/sflogo.php?group_id=69172&amp;type=1" alt="SourceForge Logo" /></a>
    <a href="http://validator.w3.org/" rel="external"><img src="get?file=images/valid-xhtml10.gif" alt="Valid XHTML 1.0!" height="31" width="88" /></a>
  </div>
EOT
 chomp($HTMLFooters);
 %News=map{$_=>1} @News unless %News;
}

sub webQuit {
 my $sref=$Tasks{$CurTaskID}->{webQuit}||=[sub{
 },sub{&jump;
  mlog(0,'quit requested from admin interface');
  doneAllTasks();
  saveDatabases(1)->();
  return <<EOT;
HTTP/1.0 200 OK
Content-type: text/html

<html>
<body>
  <h1>ASSP Terminated</h1>
</body>
</html>
EOT
  exit;
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub webLists {
 my ($http,$gpc);
 my ($t,$last_visit,$this_visit,$since,@sel_maxages,$maxage,$sel_maxage_html,$maxage_desc,$def_maxage,$sel_maxage,$s,$adr,$cnt);
 my ($ip,$range,$recs,@a,$added,$blocked,$reason,$name,$dat,$expires,$event,$ip3,$mlink,$interval,$intfmt,$hash,$color,$list);
 my ($rec,$updated,$age,$l,$cookie_exp,$cookies);
 my $sref=$Tasks{$CurTaskID}->{webLists}||=[sub{
  ($http,$gpc)=@_;
 },sub{&jump;
  $t=time;
  ($last_visit,$this_visit)=();
  if (!exists $gpc->{last_visit_lists}) {
   $last_visit=$this_visit=$t;
  } else {
   $last_visit=$gpc->{last_visit_lists};
   $this_visit=$gpc->{this_visit_lists};
  }
  if ($t-$this_visit>2*3600) {
   # entries last seen >2h ago are 'old'
   $last_visit=$this_visit;
   $this_visit=$t;
  }
  $since=localtime($last_visit);
  $since=~s/... (...) +(\d+) (........) ..(..)/$1-$2-$4 $3/;
  $gpc->{maxage_lists}=$gpc->{last_maxage_lists} if !exists $gpc->{maxage_lists} && exists $gpc->{last_maxage_lists};
  @sel_maxages=(['new','new entries',-1," - since $since"],
                ['day','last day',86400],
                ['week','last week',604800],
                ['month','last month',2592000],
                ['all','ALL ENTRIES',0]);
  ($maxage,$sel_maxage_html,$maxage_desc)=();
  $def_maxage=$sel_maxages[1][0]; # default $maxage
  $maxage=$sel_maxages[1][2];
  foreach $sel_maxage (@sel_maxages) {
   $sel_maxage_html.="            <option ";
   if (!exists $gpc->{maxage_lists}) {
    # set default $maxage
    if ($sel_maxage->[0] eq $def_maxage) {
     $sel_maxage_html.='selected="selected" ';
     $maxage=$sel_maxage->[2];
     $maxage_desc=$sel_maxage->[1].$sel_maxage->[3];
    }
   } elsif ($gpc->{maxage_lists} eq $sel_maxages[4][0]) {
    # if 'ALL ENTRIES' selected restore default (safe) selection
    if ($sel_maxage->[0] eq $def_maxage) {
     $sel_maxage_html.='selected="selected" ';
     $maxage=$sel_maxages[4][2];
     $maxage_desc=$sel_maxages[4][1];
    }
   } elsif ($gpc->{maxage_lists} eq $sel_maxage->[0]) {
    $sel_maxage_html.='selected="selected" ';
    $maxage=$sel_maxage->[2];
    $maxage_desc=$sel_maxage->[1].$sel_maxage->[3];
   }
   $sel_maxage_html.="value=\"$sel_maxage->[0]\">$sel_maxage->[1]</option>\n";
  }
  # if 'ALL ENTRIES' selected restore default (safe) selection
  $gpc->{maxage_lists}=$def_maxage if $gpc->{maxage_lists} eq $sel_maxages[4][0];
  chomp($sel_maxage_html);
  $maxage=$t-$last_visit if $maxage<0; # 'new entries' case
  ($s,$adr,$cnt)=();
  if ($gpc->{action}) {
   if ($gpc->{list} eq 'block') {
    # handle RateLimit Blocklist
    while ($gpc->{addresses}=~/((?:\d{1,3}\.){3}\d{1,3})/g) {
     $ip=$1;
     $range=ipNetwork($ip,24);
     # also check for entries, when $RateLimitUseNetblocks was enabled
     $recs=$RateLimit{$ip} || $RateLimit{$range};
     @a=split("\003",$recs);
     ($added,$blocked,$reason)=split("\004",shift @a);
     ($name,$dat)=();
     $expires=0;
     # check if blocked
     if ($blocked>=0 && $reason>=0) {
      $event=$ConfigRateLimitEvents{$reason};
      $expires=$added+$blocked+$event->{block}-$t;
      if ($expires>0) {
       $name=$event->{name};
       $dat=localtime($added+$blocked);
       $dat=~s/... (...) +(\d+) (........) ..(..)/$1-$2-$4 $3/;
      }
     }
     $s.="<div class=\"text\">$ip ";
     if ($gpc->{action} eq 'v') {
      if ($expires>0) {
       # maillog link
       ($ip3)=$ip=~/(.*)\.\d+$/;
       $mlink="$dat $ip3";
       $mlink=~s/ *$//;
       $mlink=escapeQuery($mlink);
       $mlink="logs?search=$mlink&log=slog&file=last&limit=1&nocontext=";
       $s.='<span class="negative">';
       $s.=$ip eq $range || !$RateLimit{$ip} ? 'range ' : 'address ';
       $s.='blocked=<a href="'.$mlink.'"><span style="font-weight: normal; color: red">'.$dat.'</span></a> reason='.$name.' expires='.formatTimeInterval($expires,0).'</span>';
      } else {
       $s.='<span class="positive">address/range not blocked</span>';
      }
     } elsif ($gpc->{action} eq 'a') {
      $s.='<span class="negative">action not applicable</span>';
     } elsif ($gpc->{action} eq 'r') {
      if ($expires>0) {
       ($blocked,$reason)=(-1)x2;
       # update entry
       $recs="$added\004$blocked\004$reason\003";
       $recs.=join("\003",@a)."\003" if @a;
       if ($ip eq $range || !$RateLimit{$ip}) {
        $RateLimit{$range}=$recs;
        $s.='<span class="positive">range removed</span>';
       } else {
        $RateLimit{$ip}=$recs;
        $s.='<span class="positive">address removed</span>';
       }
      } else {
       $s.='<span class="positive">address/range not blocked</span>';
      }
     }
     $s.="</div>\n";
    }
   } elsif ($gpc->{list} eq 'tuplets') {
    # handle Delaying Tuplets
    while ($gpc->{addresses}=~/((?:\d{1,3}\.){3}\d{1,3}),<?(?:$EmailAdrRe\@)?($EmailDomainRe|)>?/go) {
     $ip=$DelayUseNetblocks ? ipNetwork($1,24) : $1;
     ($interval,$intfmt)=();
     $adr=lc $2;
     if ($DelayNormalizeVERPs) {
      # strip extension
      $adr=~s/\+.*(?=@)//;
      # replace numbers with '#'
      $adr=~s/\b\d+\b(?=.*@)/#/g;
     }
     # get sender domain
     $adr=~s/.*@//;
     $hash="$ip $adr";
     $hash=Digest::MD5::md5_hex($hash) if $CanUseMD5Keys;
     $s.='<div class="text">('.$ip.','.$adr.') ';
     if ($gpc->{action} eq 'v') {
      if (!exists $DelayWhite{$hash}) {
       $s.='<span class="negative">tuplet not whitelisted</span>';
      } else {
       $interval=$t-$DelayWhite{$hash};
       $intfmt=formatTimeInterval($interval,0);
       if ($interval<$DelayExpiryTime*86400) {
        $s.='<span class="positive">tuplet whitelisted, age: '.$intfmt.'</span>';
       } else {
        $s.='<span class="positive">tuplet expired, age: '.$intfmt.'</span>';
       }
      }
     } elsif ($gpc->{action} eq 'a') {
      if (!exists $DelayWhite{$hash} || ($t-$DelayWhite{$hash}>=$DelayExpiryTime*86400)) {
       if (localMailDomain('@'.$adr)) {
        $s.='<span class="negative">local addresses not allowed on whitelisted tuplets</span>';
       } else {
        mlog(0,"whitelisted tuplets addition: ($ip,$adr) (admin)");
        $s.='<span class="positive">tuplet added</span>';
        $DelayWhite{$hash}=$t;
       }
      } else {
       $s.='<span class="positive">tuplet already whitelisted</span>';
      }
     } elsif ($gpc->{action} eq 'r') {
      if (!exists $DelayWhite{$hash}) {
       $s.='<span class="negative">tuplet not whitelisted</span>';
      } else {
       $interval=$t-$DelayWhite{$hash};
       $intfmt=formatTimeInterval($interval,0);
       if ($interval<$DelayExpiryTime*86400) {
        $s.="<span class=\"positive\">tuplet removed, age: $intfmt</span>";
       } else {
        $s.="<span class=\"positive\">expired tuplet removed, age: $intfmt</span>";
       }
       mlog(0,"whitelisted tuplets deletion: ($ip,$adr) (admin)");
       delete $DelayWhite{$hash};
      }
     }
     $s.="</div>\n";
    }
   } else {
    # handle White/Red-list
    $color=$gpc->{list} eq 'red' ? 'Red' : 'White';
    $list=$color.'list';
    while ($gpc->{addresses}=~/($EmailAdrRe\@$EmailDomainRe)/go) {
     $adr=$1;
     $s.='<div class="text">'.$adr.' ';
     $adr=lc $adr;
     if ($gpc->{action} eq 'v') {
      if ($rec=$list->{$adr}) {
       ($added,$updated)=split("\003",$rec);
       $age=$t-$added;
       $dat=localtime($added);
       $dat=~s/... (...) +(\d+) (........) ..(..)/$1-$2-$4 $3/;
       # maillog link
       $mlink="$dat addition: $adr";
       $mlink=~s/ *$//;
       $mlink=escapeQuery($mlink);
       $mlink="logs?search=$mlink&log=mlog&file=last&limit=1&nocontext=";
       $s.='<span class="positive">'.$gpc->{list}.'listed</span> added=<a href="'.$mlink.'"><span style="font-weight: normal">'.$dat.'</span></a> age='.formatTimeInterval($age,0);
      } else {
       $s.='<span class="negative">not '.$gpc->{list}.'listed</span>';
      }
     } elsif ($gpc->{action} eq 'a') {
      if ($list->{$adr}) {
       $s.='<span class="positive">already '.$gpc->{list}.'listed</span>';
      } else {
       if ($color eq 'White' && localMailDomain($adr)) {
        $s.='<span class="negative">local addresses not allowed on whitelist</span>';
       } else {
        mlog(0,"$gpc->{list}list addition: $adr (admin)");
        $s.='<span class="positive">added</span>';
        $list->{$adr}=$t;
       }
      }
     } elsif ($gpc->{action} eq 'r') {
      if ($list->{$adr}) {
       mlog(0,"$gpc->{list}list deletion: $adr (admin)");
       $s.='<span class="positive">removed</span>';
       delete $list->{$adr};
      } else {
       $s.="<span class=\"negative\">not $gpc->{list}listed</span>";
      }
     }
     $s.="</div>\n";
    }
   }
  }
  if ($gpc->{B1}=~/^Show (.)/i) {
   if ($1 eq 'B') {
    $gpc->{list}='block'; # update radios
    $s.='<div class="text"><b>RateLimit blocked addresses ('.$maxage_desc.')</b></div>';
    while (($ip,$recs)=each(%RateLimit)) {
     @a=split("\003",$recs);
     ($added,$blocked,$reason)=split("\004",shift @a);
     # check if blocked
     if ($blocked>=0 && $reason>=0) {
      $event=$ConfigRateLimitEvents{$reason};
      $expires=$added+$blocked+$event->{block}-$t;
      if ($expires>0 && (!$maxage || ($t-$added<$maxage))) {
       $name=$event->{name};
       $dat=localtime($added+$blocked);
       $dat=~s/... (...) +(\d+) (........) ..(..)/$1-$2-$4 $3/;
       # maillog link
       ($ip3)=$ip=~/(.*)\.\d+$/;
       $mlink="$dat $ip3";
       $mlink=~s/ *$//;
       $mlink=escapeQuery($mlink);
       $mlink="logs?search=$mlink&log=slog&file=last&limit=1&nocontext=";
       $s.='<div class="text">'.++$cnt.'. '.$ip;
       $s.=$ip eq ipNetwork($ip,24) ? ' range' : ' address';
       $s.=' blocked=<a href="'.$mlink.'"><span style="font-weight: normal">'.$dat.'</span></a> reason='.$name.' expires='.formatTimeInterval($expires,0).'</div>';
      }
     }
    }
   } else {
    if ($1 eq 'R') {
     $gpc->{list}='red'; # update radios
     $RedlistObject->flush() if $RedlistObject;
     open(F,"<$base/$redlistdb");
     $s.='<div class="text"><b>Redlisted addresses ('.$maxage_desc.')</b></div>';
    } else {
     $gpc->{list}='white'; # update radios
     $WhitelistObject->flush() if $WhitelistObject;
     open(F,"<$base/$whitelistdb");
     $s.='<div class="text"><b>Whitelisted addresses ('.$maxage_desc.')</b></div>';
    }
    local $/="\n";
    ($l)=();
    while ($l=<F>) {
     ($rec)=();
     ($adr,$rec)=$l=~/([^\002]*)\002(.*)/;
     ($added,$updated)=split("\003",$rec);
     $age=$t-$added;
     if (length($adr)>1 && (!$maxage || ($age<$maxage))) {
      $dat=localtime($added);
      $dat=~s/... (...) +(\d+) (........) ..(..)/$1-$2-$4 $3/;
      # maillog link
      $mlink="$dat addition: $adr";
      $mlink=~s/ *$//;
      $mlink=escapeQuery($mlink);
      $mlink="logs?search=$mlink&log=mlog&file=last&limit=1&nocontext=";
      $s.='<div class="text">'.++$cnt.'. '.$adr.' added=<a href="'.$mlink.'"><span style="font-weight: normal">'.$dat.'</span></a> age='.formatTimeInterval($age,0).'</div>';
     }
    }
    undef $/;
    close F;
   }
   $s.='<div class="text">';
   if ($cnt) {
    $s.='Found '.needEs($cnt,' entr','ies','y');
   } else {
    $s.='No entries found';
   }
   $s.='</div>';
  }
  addTooltips($s);
  # cookie expiration date
  $cookie_exp=$t+2592000; # one month
  $cookie_exp=gmtime($cookie_exp);
  $cookie_exp=~s/(...) (...) +(\d+) (........) (....)/$1, $3-$2-$5 $4 GMT/;
  $cookies;
  $cookies.="\n" if $cookies;
  $cookies.="Set-Cookie: last_visit_lists=$last_visit; expires=$cookie_exp";
  $cookies.="\n" if $cookies;
  $cookies.="Set-Cookie: this_visit_lists=$this_visit; expires=$cookie_exp";
  if (exists $gpc->{maxage_lists}) {
   $cookies.="\n" if $cookies;
   $cookies.="Set-Cookie: last_maxage_lists=$gpc->{maxage_lists}; expires=$cookie_exp";
  }
  return <<EOT;
$HTTPHeaderOK
$cookies
$HTMLHeaderDTDStrict
$HTMLHeaders
  <div class="content">
    <h2>Update or Verify Lists Entries</h2>
$s
    <form method="post" action="">
      <table class="textBox" style="width: 99%;">
        <tr>
          <td class="noBorder">Do you want to work with the:</td>
          <td class="noBorder">
            <input type="radio" name="list" value="white"${\((!$gpc->{list} || $gpc->{list} eq 'white') ? ' checked="checked" ' : ' ')} /> Whitelist or<br />
            <input type="radio" name="list" value="red"${\($gpc->{list} eq 'red' ? ' checked="checked" ' : ' ')} /> Redlist or<br />
            <input type="radio" name="list" value="tuplets"${\($gpc->{list} eq 'tuplets' ? ' checked="checked" ' : ' ')} /> Delaying Tuplets or<br />
            <input type="radio" name="list" value="block"${\($gpc->{list} eq 'block' ? ' checked="checked" ' : ' ')} /> RateLimit Blocklist
          </td>
        </tr>
        <tr>
          <td class="noBorder">Do you want to: </td>
          <td class="noBorder"><input type="radio" name="action" value="a" />add<br />
            <input type="radio" name="action" value="r" />remove<br />
            <input type="radio" checked="checked" name="action" value="v" />or verify
          </td>
          <td class="noBorder">
              List the addresses in this box:<br />
              (for tuplets put: ip-address,domain-name)<br />
              <p><textarea name="addresses" rows="4" cols="40" wrap="off">$gpc->{addresses}</textarea></p>
          </td>
        </tr>
        <tr>
          <td class="noBorder">&nbsp;</td>
          <td class="noBorder"><input type="submit" name="B1" value="  Submit  " /></td>
          <td class="noBorder">&nbsp;</td>
        </tr>
      </table>
    </form>
    <div class="textBox">
      <p>Post less than 1 megabyte of data at a time.</p>
      Note: The redlist is not a blacklist. The redlist is a list of addresses that cannot
      contribute to the whitelist, and who are not considered local, even if their mail is
      from a local computer. For example, if someone goes on a vacation and turns on their
      email's autoresponder, put them on the redlist until they return. Then as they reply
      to every spam they receive they won't corrupt your non-spam collection or whitelist.
      <form action="" method="post">
        <table style="width: 90%; margin-left: 5%;">
          <tr>
            <td align="center" class="noBorder"><input type="submit" name="B1" value="Show Whitelist" /></td>
            <td align="center" class="noBorder"><input type="submit" name="B1" value="Show Redlist" /></td>
            <td align="center" class="noBorder"><input type="submit" name="B1" value="Show Blocklist" /></td>
            <td align="center" class="noBorder">
              <select size="1" name="maxage_lists">
$sel_maxage_html
              </select>
            </td>
          </tr>
        </table>
      </form>
      <p class="warning">
        Warning: If your whitelist or redlist is long, pushing these buttons is ill-advised.
        Use these for testing and while your whitelist is short.
      </p>
    </div>
  </div>
$HTMLFooters
</body>
</html>
EOT
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub webAnalyze {
 my ($http,$gpc);
 my ($s,$st,$wl,%wl,$res,$mail,$fil,$coll,$c,$ip,$ip3,$helo,$mailfrom);
 my ($lt,$t,$nt,%seen,%got,$j,$cnt,$g,$p1,$p2,$p,@t,$v,$h,$adr,$d,$name);
 my $sref=$Tasks{$CurTaskID}->{webAnalyze}||=[sub{
  ($http,$gpc)=@_;
 },sub{&jump;
  ($s,$st,$wl,%wl,$res)=();
  $mail=$gpc->{mail};
  unless ($mail) {
   $fil=$gpc->{file};
   if ($fil) {
    ($coll)=();
    foreach $c (@Collections) {
     next unless ${$c};
     $coll=$c if $gpc->{collection} eq $c;
    }
    if ($fil=~/\.\./) {
     mlog(0,"file path not allowed while viewing corpus file '$fil'");
     $res.='<div class="text"><span class="negative">Access denied</span></div>';
    } elsif (!$coll) {
     mlog(0,"nonexistent collection not allowed while viewing corpus file '$fil'");
     $res.='<div class="text"><span class="negative">Access denied</span></div>';
    } elsif (!open(F,"<$base/${$coll}/$fil")) {
     mlog(0,"failed to open corpus file for reading '${$coll}/$fil': $!");
     $res='<div class="text"><span class="negative">'.ucfirst($!).'</span></div>';
    } else {
     binmode F;
     local $/;
     $mail=<F>;
     close F;
    }
   }
  }
  if ($mail) {
   $mail=~s/\r?\n|\r/\015\012/g;
   ($ip)=$mail=~/Received: from ([0-9\.]+).*?by\s+\Q$myName\E/is;
   ($ip3)=$ip=~/(.*)\.\d+$/;
   ($helo)=$mail=~/helo=(.*?)\)/i;
   ($mailfrom)=$mail=~/X-Assp-Envelope-From: +($EmailAdrRe\@$EmailDomainRe)/io;
   $wl='<br /><div class="text">';
   (@t)=();
   if (defined($Dnsbl{$ip}) || defined($Dnsbl{$ip3})) {
    push(@t,0.97,0.97);
    $wl.="<b>$ip dnsbl hit (adds 0.97 0.97)</b><br />\n";
   }
   if ($greylist) {
    ($v)=();
    if ($ispip && $ip=~$ISPRE) {
     if ($ispgreyvalue) {
      $v=$ispgreyvalue;
     } else {
      $v=$Greylist{x};
     }
    } else {
     $v=$Greylist{$ip3} || $Greylist{x};
    }
    if ($v) {
     push(@t,$v,$v);
     $wl.="<b>$ip has a greylist value of $v (adds $v $v)</b><br />\n";
    }
   }
   ($h)=$mail=~/^(.*?\015\012)\015\012/s;
   $wl.="<b>mail has malformed header</b><br />\n" if $h!~/^$HeaderAllCRLFRe*$/o;
   while ($mail=~/($EmailAdrRe\@$EmailDomainRe)/go) {
    $adr=$1;
    next if $wl{lc $adr}++;
    $wl.="<b>$adr is on Unprocessed Addresses list</b><br />\n" if matchSL($adr,'noProcessing');
    ($d)=$adr=~/\@(.*)/;
    next if $wl{lc $d}++;
    $wl.="<b>$d is on Blacklisted Domains list</b><br />\n" if $blackListedDomains && $adr=~$BLDRE1;
    $wl.="<b>$d is on Whitelisted Domains list</b><br />\n" if $whiteListedDomains && $adr=~$WLDRE;
    if ($Redlist{lc $adr}) {
     $wl.="<b>$adr is redlisted</b><br />\n"
    } else {
     $wl.="<b>$adr is whitelisted</b><br />\n" if $Whitelist{lc $adr};
    }
   }
   if ($helo) {
    if ($helo=~$hlSpamReRE) {
     $wl.="<b>mail matches Expression to Identify Spam HELO '$^R'</b><br />\n";
    } elsif ($HeloBlack{lc $helo}) {
     $wl.="<b>mail matches Helo blacklist '$helo'</b><br />\n";
    } elsif ($helo=~$LHNRE || $helo=~$LDRE) {
     $wl.="<b>mail has forged local helo '$helo'</b><br />\n";
    } elsif ($localDomainsFile) {
     check4update(localDomainsFile);
     if ($localDomainsFile{lc $helo}) {
      $wl.="<b>mail has forged local helo '$helo'</b><br />\n";
     }
    }
   }
   $wl.="<b>mail matches No Processing RE: '$^R'</b><br />\n" if $mail=~$npReRE;
   $wl.="<b>mail matches Local/Whitelisted No Processing RE: '$^R'</b><br />\n" if $mail=~$npLwlReRE;
   $wl.="<b>mail matches Red RE: '$^R'</b><br />\n" if $mail=~$redReRE;
   $wl.="<b>mail matches Mail Bomb RE: '$^R'</b><br />\n" if $mail=~$bombReRE;
   $wl.="<b>mail matches Script RE: '$^R'</b><br />\n" if $mail=~$scriptReRE;
   $wl.="<b>mail matches White RE: '$^R'</b><br />\n" if $mail=~$whiteReRE;
   $wl.="<b>mail matches Black RE: '$^R'</b><br />\n" if $mail=~$blackReRE;
   while ($mail=~/^Content-(?:$HeaderNameSepRe)($HeaderValueRe)name\s*=\s*($HeaderValueRe)/gimo) {
    # skip messages whose subject ends with a .com domain eg
    next if $1=~/message\/rfc822/im;
    $v=decodeMimeWords($2);
    if ($v=~$badattachRE[1]) {
     # clean and unquote
     $name=$1; $name=~tr/\r\n\t/ /; $name=~s/^[\'\"](.*)[\'\"]$/$1/;
     $wl.="<b>mail matches Level 1 Blocked File Extensions: '$name'</b><br />\n";
     last;
    } elsif ($v=~$badattachRE[2]) {
     $name=$1; $name=~tr/\r\n\t/ /; $name=~s/^[\'\"](.*)[\'\"]$/$1/;
     $wl.="<b>mail matches Level 2 Blocked File Extensions: '$name'</b><br />\n";
     last;
    } elsif ($v=~$badattachRE[3]) {
     $name=$1; $name=~tr/\r\n\t/ /; $name=~s/^[\'\"](.*)[\'\"]$/$1/;
     $wl.="<b>mail matches Level 3 Blocked File Extensions: '$name'</b><br />\n";
     last;
    }
   }
   $mail=clean(substr($mail,0,$MaxBytes));
   $wl.="<b>mail matches White RE: '$^R'</b><br />\n" if $mail=~$whiteReRE;
   $wl.="<b>mail matches Black RE: '$^R'</b><br />\n" if $mail=~$blackReRE;
   ($v,$lt,$t,$nt,%seen,%got)=();
   while ($mail=~/([-\$A-Za-z0-9\'\.!\240-\377]+)/g) {
    next if length($1)>20 || length($1)<2;
    $nt=lc $1; $nt=~s/[,.']+$//; $nt=~s/!!!+/!!/g; $nt=~s/--+/-/g;
    next unless $nt;
    $lt=$t; $t=$nt;
    next unless (length($lt)>1 || ($lt && length($t)>1));
     $j="$lt $t";
    next if $seen{$j}++>1; # first two occurances are significant
    push(@t,$v) if $v=$Spamdb{$j}; $got{$j}=$v if $v;
   }
   $cnt=0;
   $s.="<tr><th style=\"text-align: right;\"><span class=\"negative\">Bad Words</span></th>
  <th style=\"text-align: center;\"><span class=\"negative\">Bad Prob</span></th>
  <th style=\"text-align: right;\"><span class=\"positive\">Good Words</span></th>
  <th style=\"text-align: center;\"><span class=\"positive\">Good Prob</span></th></tr>\n";
   foreach (sort {abs($got{$b}-.5)<=>abs($got{$a}-.5)} keys %got) {
    $g=sprintf("%f",$got{$_});
    if ($g<0.5) {
     $s.="<tr><td></td><td></td><td align=\"right\"><span class=\"positive\">$_</span></td><td><span class=\"positive\">$g</span></td></tr>\n";
    } else {
     $s.="<tr><td align=\"right\"><span class=\"negative\">$_</span></td><td><span class=\"negative\">$g</span></td><td></td><td></td></tr>\n";
    }
    last if (($cnt++)>30);
   }
   @t=sort {abs($b-.5)<=>abs($a-.5)} @t;
   @t=@t[0..30];
   $st='<br /><b>Analysis totals:</b> ';
   foreach (@t) {
    if ($_) {
     $st.='<span class="';
     $st.=$_<0.5 ? 'positive' : 'negative';
     $st.=sprintf("\">%f</span> ",$_);
    }
   }
   $st.="<br />\n";
   $p1=1; $p2=1; foreach $p (@t) {if ($p) {$p1*=$p; $p2*=(1-$p);}}
   $p1=$p1/($p1+$p2);
   $st.='<b>Spam-prob = <span class="';
   $st.=$p1<0.6 ? 'positive' : 'negative';
   $st.=sprintf("\">%.5f</span></b>\n",$p1);
   $st.='</div>';
 #todo \n
   $mail=~s/([^\n]{70,84}[^\w\n<\@])/$1\n/g;
   $mail=~s/\s*\n+/\n/g;
   $mail=~s/<\/textarea>/\/textarea/gi;
   $mail=~s/(hlo|rcpt|ssub|href|atxt|blines|jscripttag|boldifytext|randword|linkedimage|lotsaspaces)/uc($1)/ge;
  }
  addTooltips($wl);
  return <<EOT;
$HTTPHeaderOK
$HTMLHeaderDTDStrict
$HTMLHeaders
  <div class="content">
    <h2>ASSP Mail Analyzer</h2>
    <div class="note">
      This page will show you how ASSP analyzes an email to come up with the assigned spam
      probability. You can also see how it pre-processes mail.
    </div>
$res
    $wl
    <table>
      <tr>
        <td>$s</td>
      </tr>
    </table>
    $st
    <form action="" method="post">
      <table class="textBox" style="width: 99%;">
        <tr>
          <td class="noBorder" align="center">
            Copy and paste the mail header and body here:<br />
            <textarea name="mail" rows="10" cols="75" wrap="off">$mail</textarea>
          </td>
        </tr>
        <tr>
          <td class="noBorder" align="center">
            <input type="submit" name="B1" value=" Analyze " />
          </td>
        </tr>
      </table>
    </form>
    <p class="note" >
      Note: Analysis is performed using the current spam database --
      if yours was rebuilt since the time the mail was received you'll
      receive a different result.
    </p>
    <div class="textBox">
      <p>
        To use this form using <i>Outlook Express</i> do the following. Right-click on the message
        of interest. Select <i>Properties</i>. Click the <i>Details</i> tab. Click the <i>message
        source</i> button. Right-click on the message source and click <i>Select All</i>. Right-click
        again and click <i>Copy</i>. Click on the text box above and paste (Ctrl-V perhaps). Click
        the <i>Analyze</i> button.
      </p>
      <p>
        The page will update to show you the following: if any of the email's addresses are in
        the redlist or whitelist, the most and least spammy phrases together with their spaminess,
        the resulting probabilities (probabilities may repeat one time), and the final spam probability
        score.
      </p>
    </div>
  </div>
$HTMLFooters
</body>
</html>
EOT
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub SMhelo {
 my ($fh,$l)=@_;
 reply(@_) if $l;
 my $this=$Con{$fh};
 my $client=$this->{friend};
 $l=$Con{$client}->{outgoing};
 $Con{$client}->{outgoing}='';
 if ($l=~/^ *220 / && (my $helo=$Con{$client}->{_helo})) {
  if ($sendNoopInfo) {
   $this->{getline}=\&SMskipok;
  } else {
   SMTPTraffic($client,"HELO $helo\015\012");
   # did ASSP say something to us?
   if ($Con{$client}->{outgoing}) { # yes, react
    SMfrom($fh,'');
   } else {  # no, wait for SMTP server response
    $this->{getline}=\&SMfrom;
   }
  }
 } else {
  SMdone($fh);
 }
}

sub SMskipok {
 my ($fh,$l)=@_;
 my $this=$Con{$fh};
 my $client=$this->{friend};
 slog($fh,"$l (in response to NOOP)",0,'S');
 if ($l=~/^250/ && (my $helo=$Con{$client}->{_helo})) {
  SMTPTraffic($client,"HELO $helo\015\012");
  # did ASSP say something to us?
  if ($Con{$client}->{outgoing}) { # yes, react
   SMfrom($fh,'');
  } else {  # no, wait for SMTP server response
   $this->{getline}=\&SMfrom;
  }
 } else {
  SMdone($fh);
 }
}

sub SMfrom {
 my ($fh,$l)=@_;
 reply(@_) if $l;
 my $this=$Con{$fh};
 my $client=$this->{friend};
 $l=$Con{$client}->{outgoing};
 $Con{$client}->{outgoing}='';
 if ($l=~/^ *250 /) {
  SMTPTraffic($client,"MAIL FROM:<$Con{$client}->{_from}>\015\012");
  # did ASSP say something to us?
  if ($Con{$client}->{outgoing}) { # yes, react
   SMrcpt($fh,'');
  } else {  # no, wait for SMTP server response
   $this->{getline}=\&SMrcpt;
  }
 } else {
  SMdone($fh);
 }
}

sub SMrcpt {
 my ($fh,$l)=@_;
 reply(@_) if $l;
 my $this=$Con{$fh};
 my $client=$this->{friend};
 $l=$Con{$client}->{outgoing};
 $Con{$client}->{outgoing}='';
 if ($l=~/^ *250 / && (my $rcpt=shift @{$Con{$client}->{_rcpt}})) {
  SMTPTraffic($client,"RCPT TO:<$rcpt>\015\012");
  # did ASSP say something to us?
  if ($Con{$client}->{outgoing}) { # yes, react
   SMdata($fh,'');
  } else {  # no, wait for SMTP server response
   $this->{getline}=\&SMdata;
  }
 } else {
  SMdone($fh);
 }
}

sub SMdata {
 my ($fh,$l)=@_;
 reply(@_) if $l;
 my $this=$Con{$fh};
 my $client=$this->{friend};
 $l=$Con{$client}->{outgoing};
 $Con{$client}->{outgoing}='';
 $Con{$client}->{_rcptok}=1 if $l=~/^ *250 /;
 if (my $rcpt=shift @{$Con{$client}->{_rcpt}}) {
  # continue rest of rcpt's
  SMTPTraffic($client,"RCPT TO:<$rcpt>\015\012");
  # did ASSP say something to us?
  if ($Con{$client}->{outgoing}) { # yes, react
   SMdata($fh,'');
  } else {  # no, wait for SMTP server response
   $this->{getline}=\&SMdata;
  }
 } else {
  if ($Con{$client}->{_rcptok}) {
   SMTPTraffic($client,"DATA\015\012");
   # did ASSP say something to us?
   if ($Con{$client}->{outgoing}) { # yes, react
    SMdata2($fh,'');
   } else {  # no, wait for SMTP server response
    $this->{getline}=\&SMdata2;
   }
  } else {
   SMdone($fh);
  }
 }
}

sub SMdata2 {
 my ($fh,$l)=@_;
 reply(@_) if $l;
 my $this=$Con{$fh};
 my $client=$this->{friend};
 $l=$Con{$client}->{outgoing};
 $Con{$client}->{outgoing}='';
 if ($l=~/^ *354 /) {
  $this->{getline}=\&SMdone;
  my $mail=$Con{$client}->{_body};
  while ($mail=~/(.*\015\012)/g) {
   my $line=$1;
   PeekLoop();
   SMTPTraffic($client,$line);
   last if $line=~/^\.(?:\015\012)?$/;
  }
 }
 SMdone($fh);
}

sub SMdone {
 my ($fh,$l)=@_;
 my $this=$Con{$fh};
 my $client=$this->{friend};
 doneSession($client,0) if $Con{$client}->{connected};
}

sub webSimulate {
 my ($http,$gpc)=@_;
 my ($mlog,$slog);
 my $body=decodeHTMLEntities($gpc->{body});
 unless ($body) {
  my $fil=$gpc->{file};
  if ($fil) {
   my $coll;
   foreach my $c (@Collections) {
    next unless ${$c};
    $coll=$c if $gpc->{collection} eq $c;
   }
   if ($fil=~/\.\./) {
    mlog(0,"file path not allowed while viewing corpus file '$fil'");
    $res.='<div class="text"><span class="negative">Access denied</span></div>';
   } elsif (!$coll) {
    mlog(0,"nonexistent collection not allowed while viewing corpus file '$fil'");
    $res.='<div class="text"><span class="negative">Access denied</span></div>';
   } elsif (!open(F,"<$base/${$coll}/$fil")) {
    mlog(0,"failed to open corpus file for reading '${$coll}/$fil': $!");
    $res='<div class="text"><span class="negative">'.ucfirst($!).'</span></div>';
   } else {
    binmode F;
    local $/;
    $body=<F>;
    close F;
   }
  }
 }
 if ($body) {
  $body=~s/\r?\n|\r/\015\012/g;
  my ($ip)=$body=~/Received: from ([0-9\.]+).*?by\s+\Q$myName\E/is;
  my $port=0;
  my ($ip3)=$ip=~/(.*)\.\d+$/;
  my ($helo)=$body=~/helo=(.*?)\)/i;
  my ($from)=$body=~/^(?:From|X-Assp-Envelope-From)$HeaderSepValueNgRe($EmailAdrRe\@$EmailDomainRe)/imo;
  my ($rcpt)=$body=~/^(?:To|X-Envelope-To|X-intended-for|X-original-recipient)$HeaderSepValueNgRe($EmailAdrRe\@$EmailDomainRe)/imo;
  if ($gpc->{B1}=~/run/i) {
   $ip=$gpc->{ip};
   $helo=$gpc->{helo};
   $from=$gpc->{from};
   $rcpt=$gpc->{rcpt};
  } elsif ($gpc->{B1}=~/detect/i) {
   $gpc->{ip}=$ip || $gpc->{ip};
   $gpc->{helo}=$helo || $gpc->{helo};
   $gpc->{from}=$from || $gpc->{from};
   $gpc->{rcpt}=$rcpt || $gpc->{rcpt};
  }
  if ($gpc->{B1}=~/run/i && $ip) {
   # clear out ASSP headers
   $body=~s/^X-Assp-$HeaderAllCRLFRe//gimo;
   $body=~s/^Received: from ([0-9\.]+).*?by\s+\Q$myName\E$HeaderValueCRLFRe//gimo;
   # prepare the session
   my $fh="sim$SMTPSessionID";
   NewSimSMTPConnection($fh,$ip,$port);
   my $this=$Con{$fh};
   $this->{_helo}=$helo;
   $this->{_from}=$from;
   @{$this->{_rcpt}}=$rcpt=~/($EmailAdrRe\@$EmailDomainRe)/go;
   $this->{_body}="$body\015\012.\015\012";
   while ($this->{connected}) {
    # run it !
##    MainLoop();
   }
   $mlog=$SMTPSessions{$fh}->{mlogbuf};
   $slog=$SMTPSessions{$fh}->{slogbuf};
   if ($this->{header} || $this->{body}) {
    $body="$this->{header}\015\012$this->{body}";
   }
   # chop off final 'crlf dot crlf' sequence
   $body=~s/\015\012\.(?:\015\012)?$//;
   my $sfh=$this->{sfh};
   # remove SMTP session
   delete $SMTPSessions{$sfh};
   # delete the Connection data
   delete $Con{$this->{friend}};
   delete $Con{$fh};
  }
 }
 $body=encodeHTMLEntities($body);
 addTooltips($mlog);
 addTooltips($slog);
 return <<EOT;
$HTTPHeaderOK
$HTMLHeaderDTDStrict
$HTMLHeaders
  <div class="content">
    <h2>ASSP Mail Simulator</h2>
    <div class="note">
      This page will show you how ASSP processes an email. This is only a simulation.
      No mail will actually be sent, nor lists will be updated, nor addresses blocked.
    </div>
    <div class="log">
      <pre>$mlog</pre>
    </div>
    <div class="log">
      <pre>$slog</pre>
    </div>
    <form action="" method="post">
      <table class="textBox" style="width: 99%;">
        <tr>
          <td class="noBorder" align="center">
            <table>
              <tr>
                <td align="right">Client IP <input type="text" name="ip" value="$gpc->{ip}" size="20"/></td>
                <td align="right">Mail From <input type="text" name="from" value="$gpc->{from}" size="40"/></td>
              </tr>
              <tr>
                <td align="right">HELO/EHLO <input type="text" name="helo" value="$gpc->{helo}" size="20"/></td>
                <td align="right">Recipients <input type="text" name="rcpt" value="$gpc->{rcpt}" size="40"/></td>
              </tr>
            </table>
            Copy and paste the mail header and body here:<br />
            <textarea name="body" rows="10" cols="75" wrap="off" onchange="ip.value=from.value=helo.value=rcpt.value='';">$body</textarea>
          </td>
        </tr>
        <tr>
          <td class="noBorder" align="center">
            <input type="submit" name="B1" value="Detect Envelope" />&nbsp;
            <input type="submit" name="B1" value="Run Simulation" />
          </td>
        </tr>
      </table>
    </form>
  </div>
$HTMLFooters
</body>
</html>
EOT
}

sub webLogs {
 my ($http,$gpc);
 my ($t,@sel_logs,$logs,$sel_log_html,$l,@sel_files,$maxlines,$maxfiles,$sel_file_html,$f,@sel_limits);
 my ($maxmatches,$sel_limit_html,$m,$indent,$s,$res,$pat,@sary,@logs,$matches,$lines,$files,$highlightExpr);
 my (%replace,@logs,$logf,@ary,$lastoutput,$infinity,$precontext,$postcontext,$notmatched,$currentpre,$gotmatch);
 my ($seq,$i,$j,$cur,@tokens,@good,@bad,@htokens,$token,$re,$cnt,$hpat,$cookie_exp,$cookies);
 my $sref=$Tasks{$CurTaskID}->{webLogs}||=[sub{
  ($http,$gpc)=@_;
 },sub{&jump;
  $t=time;
  $gpc->{log}=$gpc->{last_log} if !exists $gpc->{log} && exists $gpc->{last_log};
  $gpc->{file}=$gpc->{last_file} if !exists $gpc->{file} && exists $gpc->{last_file};
  $gpc->{limit}=$gpc->{last_limit} if !exists $gpc->{limit} && exists $gpc->{last_limit};
  $gpc->{nocontext}=$gpc->{last_nocontext} if !exists $gpc->{nocontext} && exists $gpc->{last_nocontext};
  $gpc->{nohighlight_m}=$gpc->{last_nohighlight_m} if !exists $gpc->{nohighlight_m} && exists $gpc->{last_nohighlight_m};
  @sel_logs=(['mlog','maillog',$logfile],
             ['slog','sessions',$slogfile]);
  ($logs,$sel_log_html)=();
  $logs=$sel_logs[0][2]; # default logs
  foreach $l (@sel_logs) {
   $sel_log_html.="              <option ";
   if ($gpc->{log} eq $l->[0]) {
    $sel_log_html.='selected="selected" ';
    $logs=$l->[2];
   }
   $sel_log_html.="value=\"$l->[0]\">$l->[1]</option>\n";
  }
  chomp($sel_log_html);
  @sel_files=(['lines','last 1000 lines',1000,0],
              ['last','last two log files',0,2],
              ['all','ALL LOG FILES',0,0]);
  ($maxlines,$maxfiles,$sel_file_html)=();
  $maxlines=$sel_files[0][2]; # default maxlines
  $maxfiles=$sel_files[0][3]; # default maxfiles
  foreach $f (@sel_files) {
   $sel_file_html.="              <option ";
   if ($gpc->{file} eq $sel_files[2][0]) {
    if ($f->[0] eq $sel_files[0][0]) {
     $sel_file_html.='selected="selected" ' ;
     $maxlines=$sel_files[2][2];
     $maxfiles=$sel_files[2][3];
     $gpc->{file}=$sel_files[0][0];
    }
   } elsif ($gpc->{file} eq $f->[0]) {
    $sel_file_html.='selected="selected" ';
    $maxlines=$f->[2];
    $maxfiles=$f->[3];
   }
   $sel_file_html.="value=\"$f->[0]\">$f->[1]</option>\n";
  }
  chomp($sel_file_html);
  @sel_limits=(['1','limit to 1 match',1],
               ['10','limit to 10 matches',10],
               ['100','limit to 100 matches',100],
               ['1000','LIMIT TO 1000 MATCHES',1000]);
  ($maxmatches,$sel_limit_html)=();
  $maxmatches=$sel_limits[1][2]; # default maxmatches
  foreach $l (@sel_limits) {
   $sel_limit_html.="              <option ";
   if ($gpc->{limit} eq $sel_limits[3][0]) {
    if ($l->[0] eq $sel_limits[1][0]) {
     $sel_limit_html.='selected="selected" ' ;
     $maxmatches=$sel_limits[3][2];
     $gpc->{limit}=$sel_limits[1][0];
    }
   } elsif ($gpc->{limit} eq $l->[0]) {
    $sel_limit_html.='selected="selected" ';
    $maxmatches=$l->[2];
   }
   $sel_limit_html.="value=\"$l->[0]\">$l->[1]</option>\n";
  }
  chomp($sel_limit_html);
  # calculate indent
  $m=localtime();
  $m=~s/^... (...) +(\d+) (\S+) ..(..)/$1-$2-$4 $3 /;
  $indent=' ' x length($m);
  # increase indent if operating on session log
  $indent.=' ' x ($ServerSessionLog ? 5 : 3) if $logs ne $sel_logs[0][2];
  ($s,$res)=();
  $pat=$gpc->{search};
  unless ($pat) {
   open(F,"<$base/$logs");
   binmode(F);
   seek(F,-$MaillogTailBytes,2) || seek(F,0,0);
   local $/;
   $s=<F>;
   close F;
   $s=encodeHTMLEntities($s);
   if ($MaillogTailWrapColumn>0) {
    $s=join('',map{logWrap("$_\n",$MaillogTailWrapColumn,$indent)} split(/\r?\n|\r/,$s));
   }
   addTooltips($s,$gpc->{nohighlight_m});
  } elsif ($CanSearchLogs) {
   (@sary,@logs)=();
   $matches=$lines=$files=0;
   ($highlightExpr,%replace)=();
   @logs=sortLogs($logs);
   $logf=File::ReadBackwards->new(shift(@logs),'\r?\n|\r',1); # line terminator regex
   if ($logf) {
    $files++;
    $pat=encodeHTMLEntities($pat);
    # normalize and strip redundand minuses
    $pat=~s/(?<!(?:-|\w))(-(?:\s+|\z))+/-/g;
    $pat=~s/\s+-$//;
    $l=$logf->readline();
    $l=~s/\r?\n|\r/\n/; # make line terminators uniform
    $l=encodeHTMLEntities($l);
    (@ary)=();
    push(@ary,$l);
    ($lastoutput,$infinity)=(10000)x2;
    ($precontext,$postcontext)=($gpc->{nocontext} ? 0 : $MaillogContextLines)x2;
    $notmatched=$currentpre=$seq=$i=$j=0;
    $cur=$ary[0];
    # normalize search pattern
    @tokens=map/^\d+\_(.*)/, sort values %{{map{lc $_ => sprintf("%02d",$i++).'_'.$_} map/(.+)/, split/(-?'[^']*')| /,$pat}};
    $pat=join(' ',@tokens);
    @good=map eval{qr/\Q$_\E/i}, map/^'?([^']*)/, map/^([^-].*)/, @tokens;
    @bad=map eval{qr/\Q$_\E/i}, map/^'?([^']*)/, map/^-(.*)/, @tokens;
    (@htokens)=();
    foreach (map/^'?([^']*)/, map/^([^-].*)/, @tokens) {
     $replace{lc $_}=$Highlights[$j % @Highlights]; # pick highlight style
     push(@htokens,quotemeta($_));
     if ($MaillogTailWrapColumn>0) {
      for ($i=length($_);$i>1;$i--) {
       # cover all possible positions of wrapping whitespaces
       $token=$_;
       $token=~s/^(.{$i}) ?/$1\n$indent/;
       $replace{lc $token}=$Highlights[$j % @Highlights];
       push(@htokens,quotemeta($token));
      }
     }
     $j++;
    }
    $highlightExpr=join('|',@htokens) if @htokens;
    while ($cur && !($maxmatches && $matches>=$maxmatches && $notmatched>$postcontext) && !($maxlines && $notmatched>=$maxlines)) {
     return cede('L1',32); L1:
     $gotmatch=1;
     $gotmatch=0 if $maxmatches && $matches>=$maxmatches;
     if ($gotmatch) {
      foreach $re (@good) {
       if ($cur!~$re) {
        $gotmatch=0;
        last;
       }
      }
     }
     if ($gotmatch) {
      foreach $re (@bad) {
       if ($cur=~$re) {
        $gotmatch=0;
        last;
       }
      }
     }
     if ($gotmatch) {
      $matches++;
      $cur=logWrap($cur,$MaillogTailWrapColumn,$indent) if $MaillogTailWrapColumn>0;
      $cur=~s/($highlightExpr)/$replace{lc $1}$1<\/span>/gi if $highlightExpr && !$gpc->{nohighlight_m};
      if ($lastoutput<=$postcontext) {
       push(@sary,$cur);
      } else {
       push(@sary,"\n") if ($seq++ && ($precontext+$postcontext>0));
       $cnt=@ary;
       for ($i=0;$i<$cnt;$i++) {
        $ary[$i]=logWrap($ary[$i],$MaillogTailWrapColumn,$indent) if $MaillogTailWrapColumn>0;
        if ($i<$precontext && $currentpre==$precontext || $i<$currentpre) {
         $ary[$i]=~s/(.*)\n$/<span class="context">$1<\/span>\n/s;
        } else {
         $ary[$i]=~s/($highlightExpr)/$replace{lc $1}$1<\/span>/gi if $highlightExpr && !$gpc->{nohighlight_m};
        }
        push(@sary,$ary[$i]);
       }
      }
      $lastoutput=0;
      $notmatched=0;
     } elsif ($lastoutput<=$postcontext) {
      $cur=logWrap($cur,$MaillogTailWrapColumn,$indent) if $MaillogTailWrapColumn>0;
      $cur=~s/(.*)\n$/<span class="context">$1<\/span>\n/s;
      push(@sary,$cur);
     }
     $lastoutput++;
     $notmatched++;
     if ($l) {
      if ($logf && $logf->eof) {
       $logf->close if exists $logf->{'handle'};
       unless ($maxfiles && $files>=$maxfiles) {
        $logf=File::ReadBackwards->new(shift(@logs),'\r?\n|\r',1);
        $files++ if $logf;
       }
      }
      $l=$logf ? $logf->readline() : '';
      $l=~s/\r?\n|\r/\n/; # make line terminators uniform
      $l=encodeHTMLEntities($l);
      $lines++;
     }
     push(@ary,$l);
     if ($currentpre<$precontext) {
      $currentpre++;
     } else {
      shift(@ary);
     }
     $cur=$ary[$currentpre];
    }
    $logf->close if exists $logf->{'handle'};
   }
   $hpat=$pat;
   $hpat=~s/($highlightExpr)/$replace{lc $1}$1<\/span>/gi if $highlightExpr && !$gpc->{nohighlight_m};
   if ($matches>0) {
    if ($MaillogTailWrapColumn>0) {
     # wipe out highlighted wrapping whitespaces
     s/(\n\Q$indent\E)/<span style="background-color:white">$1<\/span>/g foreach @sary;
    }
    $s=join('',reverse @sary);
    $res='Found '.needEs($matches,' matching line','s').' for \''.$hpat.'\', searched in '.needEs($files,' log file','s').
         ' ('.needEs($lines,' line','s').'), search took '.formatTimeInterval(time-$t,0).'.';
   } else {
    $res='No results found for \''.$hpat.'\', searched in '.needEs($files,' log file','s').
         ' ('.needEs($lines,' line','s').'), search took '.formatTimeInterval(time-$t,0).'.';
   }
   addTooltips($res,$gpc->{nohighlight_m});
   addTooltips($s,$gpc->{nohighlight_m});
  } else {
   $s='<p class="warning">Please install required module <a href="http://search.cpan.org/~uri/File-ReadBackwards-1.04/" rel="external">File::ReadBackwards</a>.</p>';
  }
  # cookie expiration date
  $cookie_exp=$t+2592000; # one month
  $cookie_exp=gmtime($cookie_exp);
  $cookie_exp=~s/(...) (...) +(\d+) (........) (....)/$1, $3-$2-$5 $4 GMT/;
  ($cookies)=();
  if (exists $gpc->{log}) {
   $cookies.="\n" if $cookies;
   $cookies.="Set-Cookie: last_log=$gpc->{log}; expires=$cookie_exp";
  }
  if (exists $gpc->{file}) {
   $cookies.="\n" if $cookies;
   $cookies.="Set-Cookie: last_file=$gpc->{file}; expires=$cookie_exp";
  }
  if (exists $gpc->{limit}) {
   $cookies.="\n" if $cookies;
   $cookies.="Set-Cookie: last_limit=$gpc->{limit}; expires=$cookie_exp";
  }
  if (exists $gpc->{nocontext}) {
   $cookies.="\n" if $cookies;
   $cookies.="Set-Cookie: last_nocontext=$gpc->{nocontext}; expires=$cookie_exp";
  }
  if (exists $gpc->{nohighlight_m}) {
   $cookies.="\n" if $cookies;
   $cookies.="Set-Cookie: last_nohighlight_m=$gpc->{nohighlight_m}; expires=$cookie_exp";
  }
  return <<EOT;
$HTTPHeaderOK
$cookies
$HTMLHeaderDTDStrict
$HTMLHeaders
  <div class="content">
    <h2>ASSP Maillog Tail</h2>
    <div class="note">
      Press your browser's refresh to update this screen. Newest entries are at the end.
      Use single quotes for phrases. Use minus sign to negate a search term.
    </div>
    <form action="" method="get">
      <table class="textBox" style="width: 99%;">
        <tr>
          <td class="noBorder" align="right">
            <input type="text" name="search" value="$pat" size="30"/>
            <input type="submit" value="Search" />
          </td>
          <td class="noBorder" align="center">
            <select size="1" name="log">
$sel_log_html
            </select>
            <select size="1" name="file">
$sel_file_html
            </select><br />
            <select size="1" name="limit">
$sel_limit_html
            </select>
          </td>
          <td class="noBorder">
            <input type="hidden" name="nocontext" value="$gpc->{nocontext}">
            <input type="checkbox" name="nocontext_checkbox"${\($gpc->{nocontext} ? ' checked="checked" ' : ' ')}value='1' onclick="this.form['nocontext'].value=this.checked ? '1' : '0';"/>hide&nbsp;context&nbsp;lines<br />
            <input type="hidden" name="nohighlight_m" value="$gpc->{nohighlight_m}">
            <input type="checkbox" name="nohighlight_m_checkbox"${\($gpc->{nohighlight_m} ? ' checked="checked" ' : ' ')}value='1' onclick="this.form['nohighlight_m'].value=this.checked ? '1' : '0';"/>disable&nbsp;highlighting
          </td>
        </tr>
      </table>
    </form>
    <div class="log">
      $res
      <pre>$s</pre>
    </div>
  </div>
$HTMLFooters
</body>
</html>
EOT
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub webCorpusItem {
 my ($coll,$fn,$det,$gpc,$good,$bad)=@_;
 return '' unless defined $det->[0];
 return '' if $gpc->{nomoved} && ($det->[4] & 2);
 if (@{$good} || @{$bad}) {
  PeekLoop();
  open(I,"$base/${$coll}/$fn");
  binmode(I);
  local $/;
  my $c=<I>;
  undef $/;
  close I;
  $c=encodeHTMLEntities($c);
  my $gotmatch=1;
  foreach my $re (@{$good}) {
   if ($c!~$re) {
    $gotmatch=0;
    last;
   }
  }
  if ($gotmatch) {
   foreach my $re (@{$bad}) {
    if ($c=~$re) {
     $gotmatch=0;
     last;
    }
   }
  }
  return '' unless $gotmatch;
 }
 my $sub=$det->[3];
 my $lt=localtime($det->[0]);
 my $dat=$lt;
 $dat=~s/... (...) +(\d+) (........) ..(..)/$1-$2-$4 $3/;
 # maillog link
 my $mlink=$lt;
 $mlink=~s/... (...) +(\d+) ........ ..(..)/$1-$2-$3/;
 $mlink.=" $det->[1]";
 $mlink=~s/ *$//;
 $mlink=escapeQuery($mlink);
 $mlink="logs?search=$mlink&log=mlog&file=last&limit=1&nocontext=";
 # view file link
 my $vlink=$gpc->{search};
 # javascript 'touches' the url that passes through it, hence double-encoding
 $vlink=escapeQuery(escapeQuery($vlink));
 $vlink="javascript:popFileViewer('$coll','$fn','$vlink');";
 # if file is old or has 'seen' bit set
 if ($det->[0]<=$last_visit || $det->[4] & 1) {
  $sub='<span style="font-weight: normal">'.$sub.'</span>';
  $dat='<span style="font-weight: normal">'.$dat.'</span>';
 }
 # if file has 'moved' bit set
 if ($det->[4] & 2) {
  $sub='<span class="neutral">'.$sub.'</span>';
  $dat='<span class="neutral">'.$dat.'</span>';
 }
 return <<EOT;
        <tr>
          <td class="statsTitle"><input type="checkbox" name="items[]" value="$coll|$fn"></td>
          <td class="statsTitle"><a onClick="this.style.fontWeight='normal';" href="$vlink">$sub</a></td>
          <td class="optionValue"><a onClick="this.style.fontWeight='normal';" href="$mlink">$dat</a></td>
          <td class="optionValue">$det->[1]</td>
          <td class="optionValue">$det->[2]</td>
        </tr>
EOT
}

sub webCorpus {
 my ($http,$gpc);
 my ($t,$last_visit,$this_visit,$since,@sel_colls,$coll,$sel_coll_html,$coll_desc,$def_coll,$c,@sel_maxages,$sel_maxage);
 my ($maxage,$sel_maxage_html,$maxage_desc,$def_maxage,@sel_acts,$sel_act,$act,$sel_act_html,$act_desc,$def_act);
 my ($s,$res,$done,$i,$icoll,$fil,$coll2,$det,$f,$nf,$pat,@tokens,@good,@bad,$matches,%dir2coll,$l,%s,$fil2,$rec);
 my ($dir,@arr,$det2,$flags,$res2,@items,$hpat,%replace,@htokens,$highlightExpr,$cookie_exp,$cookies,@dir,$n,$fil3);
 my $sref=$Tasks{$CurTaskID}->{webCorpus}||=[sub{
  ($http,$gpc)=@_;
 },sub{&jump;
  unless ($EnableCorpusInterface) {
   return <<EOT;
HTTP/1.0 200 OK
Content-type: text/html

<html>
<body>
  <h1>Corpus Interface disabled</h1>
</body>
</html>
EOT
  }
  $t=time;
  ($last_visit,$this_visit)=();
  if (!exists $gpc->{last_visit_corpus}) {
   $last_visit=$this_visit=$t;
  } else {
   $last_visit=$gpc->{last_visit_corpus};
   $this_visit=$gpc->{this_visit_corpus};
  }
  if ($t-$this_visit>2*3600) {
   # files last seen >2h ago are 'old'
   $last_visit=$this_visit;
   $this_visit=$t;
  }
  $since=localtime($last_visit);
  $since=~s/... (...) +(\d+) (........) ..(..)/$1-$2-$4 $3/;
  $gpc->{collection}=$gpc->{last_collection} if !exists $gpc->{collection} && exists $gpc->{last_collection};
  $gpc->{maxage_corpus}=$gpc->{last_maxage_corpus} if !exists $gpc->{maxage_corpus} && exists $gpc->{last_maxage_corpus};
  $gpc->{action}=$gpc->{last_action} if !exists $gpc->{action} && exists $gpc->{last_action};
  $gpc->{nomoved}=$gpc->{last_nomoved} if !exists $gpc->{nomoved} && exists $gpc->{last_nomoved};
  $gpc->{nohighlight_c}=$gpc->{last_nohighlight_c} if !exists $gpc->{nohighlight_c} && exists $gpc->{last_nohighlight_c};
  @sel_colls=(['notspamlog','not-spam collection'],
              ['spamlog','spam collection'],
              ['incomingOkMail','mail-ok collection'],
              ['viruslog','virus collection'],
              ['correctednotspam','not-spam reports'],
              ['correctedspam','spam reports'],
              ['_ham','* passed ham *'], # combined collections
              ['_spam','* passed spam *'], # combined collections
              ['_blocked','* blocked spam *']); # combined collections
  ($coll,$sel_coll_html,$coll_desc)=();
  $def_coll=$sel_colls[0][0]; # default $coll
  $coll=$def_coll;
  foreach $c (@sel_colls) {
   next unless ${$c->[0]} || $c->[0]=~/^_/;
   $sel_coll_html.="            <option ";
   if (!exists $gpc->{collection}) {
    # set default $coll
    if ($c->[0] eq $def_coll) {
     $sel_coll_html.='selected="selected" ';
     $coll=$c->[0];
     $coll_desc=$c->[1];
    }
   } elsif ($gpc->{collection} eq $c->[0]) {
    $sel_coll_html.='selected="selected" ';
    $coll=$c->[0];
    $coll_desc=$c->[1];
   }
   $sel_coll_html.="value=\"$c->[0]\">$c->[1]</option>\n";
  }
  chomp($sel_coll_html);
  @sel_maxages=(['new','new files',-1," - since $since"],
                ['day','last day',86400],
                ['week','last week',604800],
                ['month','last month',2592000],
                ['all','ALL FILES',0]);
  ($maxage,$sel_maxage_html,$maxage_desc)=();
  $def_maxage=$sel_maxages[1][0]; # default $maxage
  $maxage=$sel_maxages[1][2];
  foreach $sel_maxage (@sel_maxages) {
   $sel_maxage_html.="            <option ";
   if (!exists $gpc->{maxage_corpus}) {
    # set default $maxage
    if ($sel_maxage->[0] eq $def_maxage) {
     $sel_maxage_html.='selected="selected" ';
     $maxage=$sel_maxage->[2];
     $maxage_desc=$sel_maxage->[1].$sel_maxage->[3];
    }
   } elsif ($gpc->{maxage_corpus} eq $sel_maxages[4][0]) {
    # if 'ALL FILES' selected restore default (safe) selection
    if ($sel_maxage->[0] eq $def_maxage) {
     $sel_maxage_html.='selected="selected" ';
     $maxage=$sel_maxages[4][2];
     $maxage_desc=$sel_maxages[4][1];
    }
   } elsif ($gpc->{maxage_corpus} eq $sel_maxage->[0]) {
    $sel_maxage_html.='selected="selected" ';
    $maxage=$sel_maxage->[2];
    $maxage_desc=$sel_maxage->[1].$sel_maxage->[3];
   }
   $sel_maxage_html.="value=\"$sel_maxage->[0]\">$sel_maxage->[1]</option>\n";
  }
  # if 'ALL FILES' selected restore default (safe) selection
  $gpc->{maxage_corpus}=$def_maxage if $gpc->{maxage_corpus} eq $sel_maxages[4][0];
  chomp($sel_maxage_html);
  @sel_acts=(['notspamlog','move to not-spam collection'],
             ['spamlog','move to spam collection'],
             ['incomingOkMail','move to mail-ok collection'],
             ['viruslog','move to virus collection'],
             ['correctednotspam','move to not-spam reports'],
             ['correctedspam','move to spam reports'],
             ['delete','DELETE']);
  ($act,$sel_act_html,$act_desc)=();
  $def_act=$sel_acts[0][0]; # default $act
  $act=$def_act;
  foreach $sel_act (@sel_acts) {
   next unless $sel_act->[0] eq 'delete' || ${$sel_act->[0]} && $sel_act->[0] ne $coll;
   $sel_act_html.="              <option ";
   if (!exists $gpc->{action}) {
    # set default $act
    if ($sel_act->[0] eq $def_act) {
     $sel_act_html.='selected="selected" ';
     $act=$sel_act->[0];
     $act_desc=$sel_act->[1];
    }
   } elsif ($gpc->{action} eq $sel_acts[6][0]) {
    # if 'DELETE' selected restore default (safe) selection
    if ($sel_act->[0] eq $def_act) {
     $sel_act_html.='selected="selected" ';
     $act=$sel_acts[6][0];
     $act_desc=$sel_acts[6][1];
    }
   } elsif ($gpc->{action} eq $sel_act->[0]) {
    $sel_act_html.='selected="selected" ';
    $act=$sel_act->[0];
    $act_desc=$sel_act->[1];
   }
   $sel_act_html.="value=\"$sel_act->[0]\">$sel_act->[1]</option>\n";
  }
  # if 'DELETE' selected restore default (safe) selection
  $gpc->{action}=$def_act if $gpc->{action} eq $sel_acts[6][0];
  chomp($sel_act_html);
  $maxage=$t-$last_visit if $maxage<0; # 'new files' case
  ($s,$res)=();
  $done=0;
  foreach $i (@{$gpc->{'items[]'}}) {
   ($icoll,$fil)=$i=~/(.*)\|(.*)/;
   ($coll2)=();
   foreach $c (@Collections) {
    next unless ${$c};
    $coll2=$c if $icoll eq $c;
   }
   if ($fil=~/\.\./) {
    mlog(0,"file path not allowed while moving/deleting corpus file '$fil'");
    $res='<div class="text"><span class="negative">Access denied</span></div><br />';
    last;
   } elsif (!$coll2) {
    mlog(0,"nonexistent collection not allowed while moving/deleting corpus file '$fil'");
    $res='<div class="text"><span class="negative">Access denied</span></div><br />';
    last;
   } elsif ($act eq 'delete') {
    unlink("$base/${$coll2}/$fil");
    # remove cache entry
##    corpusDetails("${$coll2}/$fil",1);
    return call('L1',corpusDetails("${$coll2}/$fil",1)); L1:
    $done++;
   } else {
##    $det=corpusDetails("${$coll2}/$fil",0);
    return call('L2',corpusDetails("${$coll2}/$fil")); L2:
    $det=shift;
    next unless defined $det->[0];
    $f="$base/${$coll2}/$fil";
    $nf=$f;
    # move2num
    if ($fil=~/(\d+)$maillogExt$/i && $1<$MaxFiles) {
     $nf=~s/.*[\\\/]|/${$act}\//;
    } else {
     $nf=getNewCollFileName(${$act});
     $nf="${$act}/$nf$maillogExt";
    }
    if (-e $f && !samePaths($f,"$base/$nf")) {
     unlink("$base/$nf");
     if (rename($f,"$base/$nf")) {
      # remove old entry
##      corpusDetails("${$coll2}/$fil",1);
      return call('L3',corpusDetails("${$coll2}/$fil",1)); L3:
      # reload new entry, turn on 'moved' bit in flags field
##      corpusSetFlags($nf,($det->[4])|2,1);
      return call('L4',corpusSetFlags($nf,($det->[4])|2,1)); L4:
      $done++;
     } else {
      mlog(0,"failed to move corpus file from '$f' to '$base/$nf': $!");
      # reload new entry
##      corpusDetails($nf,1);
      return call('L5',corpusDetails($nf,1)); L5:
     }
    }
   }
  }
  $res.='\''.$act_desc.'\' action was performed on '.needEs($done,' file','s').
        ($coll=~/^_/ ? '' : ' from '.$coll_desc).'.<br />' if $done>0;
  $pat=$gpc->{search};
  $pat=encodeHTMLEntities($pat);
  # normalize and strip redundand minuses
  $pat=~s/(?<!(?:-|\w))(-(?:\s+|\z))+/-/g;
  $pat=~s/\s+-$//;
  # normalize search pattern
  $i=0;
  @tokens=map/^\d+\_(.*)/, sort values %{{map{lc $_ => sprintf("%02d",$i++).'_'.$_} map/(.+)/, split/(-?'[^']*')| /,$pat}};
  $pat=join(' ',@tokens);
  @good=map eval{qr/\Q$_\E/i}, map/^'?([^']*)/, map/^([^-].*)/, @tokens;
  @bad=map eval{qr/\Q$_\E/i}, map/^'?([^']*)/, map/^-(.*)/, @tokens;
  $matches=0;
  if ($coll=~/^_/) {
   # handle combined collections
   %dir2coll=reverse map{$_=>${$_}} @Collections;
   $CorpusObject->flush() if $CorpusObject;
   open(F,"<$base/$corpusdb");
   local $/="\n";
   ($l,%s)=();
   while ($l=<F>) {
    ($fil2,$rec)=$l=~/([^\002]*)\002(.*)/;
    ($dir)=();
    ($dir,$fil2)=$fil2=~/(.*)[\\\/](.*)/;
    @arr=split("\003",$rec);
    $det2=\@arr;
    next unless defined $det2->[0] && (!$maxage || $t-($det2->[0])<$maxage);
    $flags=$det2->[4] & 12;
    next unless $coll eq '_ham' && $flags==8 ||
                $coll eq '_spam' && $flags==12 ||
                $coll eq '_blocked' && $flags==4;
    if ($res2=webCorpusItem($dir2coll{$dir},$fil2,$det2,$gpc,\@good,\@bad)) {
     $s{$det2->[0].$fil2}=$res2;
     $matches++;
    }
   }
   close F;
   $s.=join('',map{$s{$_}} reverse sort keys %s);
  } else {
##   opendir(DIR,"$base/${$coll}");
##   @items=sort{$b->[1]<=>$a->[1]}
##          grep{defined $_->[1] && (!$maxage || $t-($_->[1])<$maxage)}
##          map{[$_,corpus("${$coll}/$_",0)->[0]]}
##          readdir DIR;
##   closedir(DIR);
##   foreach $i (@items) {
##    if ($res2=webCorpusItem($coll,$i->[0],corpusDetails("${$coll}/$i->[0]",0),$gpc,\@good,\@bad)) {
##     $s.=$res2;
##     $matches++;
##    }
##   }

   opendir(DIR,"$base/${$coll}");
   @dir=readdir DIR;
   closedir(DIR);
   (@items)=();
   for ($n=0;$n<@dir;$n++) {
    $fil3=$dir[$n];
    return call('L6',corpus("${$coll}/$fil3")); L6:
    push(@items,[$fil3,(shift)->[0]]);
   }
   @items=sort{$b->[1]<=>$a->[1]}
          grep{defined $_->[1] && (!$maxage || $t-($_->[1])<$maxage)}
          @items;
   for ($n=0;$n<@items;$n++) {
    $i=$items[$n];
    return call('L7',corpusDetails("${$coll}/$i->[0]")); L7:
    if ($res2=webCorpusItem($coll,$i->[0],shift,$gpc,\@good,\@bad)) {
     $s.=$res2;
     $matches++;
    }
   }

  }
  chomp($s);
  if ($s) {
   $s=<<EOT;
    <form action="" method="post">
      <input type="hidden" name="collection" value="$coll">
      <table class="statBox" style="width: 99%">
        <tr>
          <td class="contentHead" style="width: 1%"><input type="checkbox" onClick="check(this.form['items[]']);"></td>
          <td class="contentHead" style="width: 44%">Subject</td>
          <td class="contentHead" style="width: 25%">Date</td>
          <td class="contentHead" style="width: 15%">From</td>
          <td class="contentHead" style="width: 15%">To</td>
        </tr>
$s
      </table>
      <br />
      <table class="textBox" style="width: 99%;">
        <tr>
          <td class="noBorder" align="right">
            Selected files:
            <select size="1" name="action">
$sel_act_html
            </select>
            <input type="submit" value="Execute" />
          </td>
        </tr>
      </table>
    </form>
EOT
   chomp($s);
  };
  $hpat=$pat;
  if ($pat && !$gpc->{nohighlight_c}) {
   $i=0;
   (%replace,@htokens,$highlightExpr)=();
   foreach (map/^'?([^']*)/, map/^([^-].*)/, @tokens) {
    $replace{lc $_}=$Highlights[$i % @Highlights]; # pick highlight style
    push(@htokens,quotemeta($_));
    $i++;
   }
   if (@htokens) {
    $highlightExpr=join('|',@htokens);
    $hpat=~s/($highlightExpr)/$replace{lc $1}$1<\/span>/gi;
   }
  }
  if ($matches>0) {
   if ($pat) {
    $res.='Found '.needEs($matches,' matching file','s').' for \''.$hpat.'\', searched in '.$coll_desc.
          ' ('.$maxage_desc.'), search took '.formatTimeInterval(time-$t,0).'.';
   } else {
    $res.='Found '.needEs($matches,' file','s').' in '.$coll_desc.
          ' ('.$maxage_desc.'), search took '.formatTimeInterval(time-$t,0).'.';
   }
  } else {
   if ($pat) {
    $res.='No results found for \''.$hpat.'\', searched in '.$coll_desc.
          ' ('.$maxage_desc.'), search took '.formatTimeInterval(time-$t,0).'.';
   } else {
    $res.='No files found in '.$coll_desc.
          ' ('.$maxage_desc.'), search took '.formatTimeInterval(time-$t,0).'.';
   }
  }
  # cookie expiration date
  $cookie_exp=$t+2592000; # one month
  $cookie_exp=gmtime($cookie_exp);
  $cookie_exp=~s/(...) (...) +(\d+) (........) (....)/$1, $3-$2-$5 $4 GMT/;
  ($cookies)=();
  $cookies.="\n" if $cookies;
  $cookies.="Set-Cookie: last_visit_corpus=$last_visit; expires=$cookie_exp";
  $cookies.="\n" if $cookies;
  $cookies.="Set-Cookie: this_visit_corpus=$this_visit; expires=$cookie_exp";
  if (exists $gpc->{collection}) {
   $cookies.="\n" if $cookies;
   $cookies.="Set-Cookie: last_collection=$gpc->{collection}; expires=$cookie_exp";
  }
  if (exists $gpc->{maxage_corpus}) {
   $cookies.="\n" if $cookies;
   $cookies.="Set-Cookie: last_maxage_corpus=$gpc->{maxage_corpus}; expires=$cookie_exp";
  }
  if (exists $gpc->{action}) {
   $cookies.="\n" if $cookies;
   $cookies.="Set-Cookie: last_action=$gpc->{action}; expires=$cookie_exp";
  }
  if (exists $gpc->{nomoved}) {
   $cookies.="\n" if $cookies;
   $cookies.="Set-Cookie: last_nomoved=$gpc->{nomoved}; expires=$cookie_exp";
  }
  if (exists $gpc->{nohighlight_c}) {
   $cookies.="\n" if $cookies;
   $cookies.="Set-Cookie: last_nohighlight_c=$gpc->{nohighlight_c}; expires=$cookie_exp";
  }
  return <<EOT;
$HTTPHeaderOK
$cookies
$HTMLHeaderDTDTransitional
$HTMLHeaders
  <div class="content">
    <h2>ASSP Corpus</h2>
    <form action="" method="get">
      <table class="textBox" style="width: 99%;">
        <tr>
           <td class="noBorder" align="right">
            <input type="text" name="search" value="$pat" size="30"/>
            <input type="submit" value="Search" />
          </td>
          <td class="noBorder" align="center">
            <select size="1" name="collection">
$sel_coll_html
            </select>
            <select size="1" name="maxage_corpus">
$sel_maxage_html
            </select>
          </td>
          <td class="noBorder">
            <input type="hidden" name="nomoved" value="$gpc->{nomoved}">
            <input type="checkbox" name="nomoved_checkbox"${\($gpc->{nomoved} ? ' checked="checked" ' : ' ')}value='1' onclick="this.form['nomoved'].value=this.checked ? '1' : '0';"/>hide&nbsp;moved&nbsp;files<br />
            <input type="hidden" name="nohighlight_c" value="$gpc->{nohighlight_c}">
            <input type="checkbox" name="nohighlight_c_checkbox"${\($gpc->{nohighlight_c} ? ' checked="checked" ' : ' ')}value='1' onclick="this.form['nohighlight_c'].value=this.checked ? '1' : '0';"/>disable&nbsp;highlighting
          </td>
        </tr>
      </table>
    </form>
    <div class="log">
$res
$s
    </div>
  </div>
$HTMLFooters
</body>
</html>
EOT
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub webView {
 my ($http,$gpc);
 my ($t,@colls,$coll,$coll_desc,$c,@sel_acts,$act,$sel_act_html,$def_act,$sel_act,$s,$res);
 my ($fil,$pat,$i,@tokens,%replace,@htokens,$highlightExpr,@offsets,$h,$b,$len,$index,$left);
 my ($right,$ret,$cols,$o,$char,$temp,$det,$cookie_exp,$cookies,$JavaScript,$HTMLHeaders);
 my $sref=$Tasks{$CurTaskID}->{webView}||=[sub{
  ($http,$gpc)=@_;
 },sub{&jump;
  unless ($EnableCorpusInterface) {
   return <<EOT;
HTTP/1.0 200 OK
Content-type: text/html

<html>
<body>
  <h1>Corpus Interface disabled</h1>
</body>
</html>
EOT
  }
  $t=time;
  $gpc->{hexview}=$gpc->{last_hexview} if !exists $gpc->{hexview} && exists $gpc->{last_hexview};
  $gpc->{nohighlight_c}=$gpc->{last_nohighlight_c} if !exists $gpc->{nohighlight_c} && exists $gpc->{last_nohighlight_c};
  @colls=(['notspamlog','not-spam collection'],
          ['spamlog','spam collection'],
          ['incomingOkMail','mail-ok collection'],
          ['viruslog','virus collection'],
          ['correctednotspam','not-spam reports'],
          ['correctedspam','spam reports']);
  ($coll,$coll_desc)=();
  foreach $c (@colls) {
   next unless ${$c->[0]};
   if ($gpc->{collection} eq $c->[0]) {
    $coll=$c->[0];
    $coll_desc=$c->[1];
   }
  }
  @sel_acts=(['notspamlog','move to not-spam collection'],
             ['spamlog','move to spam collection'],
             ['incomingOkMail','move to mail-ok collection'],
             ['viruslog','move to virus collection'],
             ['correctednotspam','move to not-spam reports'],
             ['correctedspam','move to spam reports'],
             ['delete','DELETE']);
  ($act,$sel_act_html)=();
  $def_act=$sel_acts[0][0]; # default $act
  $act=$def_act;
  foreach $sel_act (@sel_acts) {
   next unless $sel_act->[0] eq 'delete' || ${$sel_act->[0]} && $sel_act->[0] ne $coll;
   $sel_act_html.="            <option ";
   if (!exists $gpc->{last_action}) {
    # set default $act
    if ($sel_act->[0] eq $def_act) {
     $sel_act_html.='selected="selected" ';
     $act=$sel_act->[0];
    }
   } elsif ($gpc->{last_action} eq $sel_act->[0]) {
    $sel_act_html.='selected="selected" ';
    $act=$sel_act->[0];
   }
   $sel_act_html.="value=\"$sel_act->[0]\">$sel_act->[1]</option>\n";
  }
  chomp($sel_act_html);
  ($s,$res)=();
  $fil=$gpc->{file};
  $pat=$gpc->{search};
  if ($fil=~/\.\./) {
   mlog(0,"file path not allowed while viewing corpus file '$fil'");
   $res.='<div class="text"><span class="negative">Access denied</span></div>';
  } elsif (!$coll) {
   mlog(0,"nonexistent collection not allowed while viewing corpus file '$fil'");
   $res.='<div class="text"><span class="negative">Access denied</span></div>';
  } elsif (!open(F,"<$base/${$coll}/$fil")) {
   mlog(0,"failed to open corpus file for reading '${$coll}/$fil': $!");
   $res='<div class="text"><span class="negative">'.ucfirst($!).'</span></div>';
  } else {
   binmode F;
   local $/;
   $s=<F>;
   close F;
   $pat=encodeHTMLEntities($pat) unless $gpc->{hexview};
   # normalize and strip redundand minuses
   $pat=~s/(?<!(?:-|\w))(-(?:\s+|\z))+/-/g;
   $pat=~s/\s+-$//;
   # normalize search pattern
   $i=0;
   @tokens=map/^\d+\_(.*)/, sort values %{{map{lc $_ => sprintf("%02d",$i++).'_'.$_} map/(.+)/, split/(-?'[^']*')| /,$pat}};
   $pat=join(' ',@tokens);
   (%replace,@htokens,$highlightExpr)=();
   if ($pat && !$gpc->{nohighlight_c}) {
    $i=0;
    foreach (map/^'?([^']*)/, map/^([^-].*)/, @tokens) {
     $replace{lc $_}=$Highlights[$i % @Highlights]; # pick highlight style
     push(@htokens,quotemeta($_));
     $i++;
    }
   }
   if ($gpc->{hexview}) {
    # handle hexadecimal view
    (@offsets)=();
    ($h,$b)=$s=~/^(.*?\015\012)\015\012(.*)/s;
    # mark out important headers
    while ($h=~/^(?:Received|From|To|Date|Subject)$HeaderSepValueRe/gimo) {
     push(@offsets,[@-[0],@+[0],'<b>','</b>']);
    }
    $s="$h\015\012$b";
    # highlight search terms
    if ($pat && !$gpc->{nohighlight_c} && @htokens) {
     $highlightExpr=join('|',@htokens);
     while ($s=~/($highlightExpr)/gi) {
      push(@offsets,[@-[0],@+[0],$replace{lc $1},'</span>']);
     }
    }
    # highlight bare linefeeds
    while ($s=~/\015(?!\012)|(?<!\015)\012/g) {
     push(@offsets,[@-[0],@+[0],'<span style="color:black; background-color:red">','</span>']);
    }
    $len=length($s);
    ($index,$left,$right,$ret)=();
    $cols=16;
    while ($index<$len) {
     return cede('L1',32); L1:
     foreach $o (@offsets) {
      if ($index>=$o->[0] && $index<$o->[1]) {
       $left.=$o->[2];
       $right.=$o->[2];
      }
     }
     $char=substr($s,$index,1);
     $left.=sprintf("%02x",ord $char);
     $char=~tr/\040-\176/./c;
     $right.=encodeHTMLEntities($char);
     foreach $o (@offsets) {
      if ($index>=$o->[0] && $index<$o->[1]) {
       $left.=$o->[3];
       $right.=$o->[3];
      }
     }
     $left.=' ';
     unless ((++$index % $cols) && $index<$len) {
      $temp=(($index-1) % $cols)+1;
      $ret.=sprintf("%08x ",$index-$temp).(' ' x 2).$left.('   ' x ($cols-$temp)).(' ' x 2).$right."\n";
      ($left,$right)='';
     }
    }
    $s=$ret;
   } else {
    # handle normal view
    $s=encodeHTMLEntities($s);
    ($h,$b)=$s=~/^(.*?\015\012)\015\012(.*)/s;
    # mark out important headers
    $h=~s/^((?:Received|From|To|Date|Subject)$HeaderSepValueRe)/<b>$1<\/b>/gimo;
    $s="$h\015\012$b";
    # highlight search terms
    if ($pat && !$gpc->{nohighlight_c} && @htokens) {
     $highlightExpr=join('|',@htokens);
     $s=~s/($highlightExpr)/$replace{lc $1}$1<\/span>/gi if $highlightExpr;
    }
    # highlight bare linefeeds
    $s=~s/\015([^\012])/<span style="color:black; background-color:red">\\cr<\/span>\015\012$1/g;
    $s=~s/([^\015])\012/$1<span style="color:black; background-color:red">\\lf<\/span>\015\012/g;
   }
   $res="Contents of the $fil file ($coll_desc):";
##   $det=corpusDetails("${$coll}/$fil",0);
   return call('L2',corpusDetails("${$coll}/$fil")); L2:
   $det=shift;
   # if file has 'moved' bit set
   $res='<span class="neutral">'.$res.'</span>' if $det->[4] & 2;
   # turn on 'seen' bit in flags field
##   corpusSetFlags("${$coll}/$fil",($det->[4])|1,0);
   return call('L3',corpusSetFlags("${$coll}/$fil",($det->[4])|1)); L3:
  }
  # cookie expiration date
  $cookie_exp=$t+2592000; # one month
  $cookie_exp=gmtime($cookie_exp);
  $cookie_exp=~s/(...) (...) +(\d+) (........) (....)/$1, $3-$2-$5 $4 GMT/;
  ($cookies)=();
  if (exists $gpc->{hexview}) {
   $cookies.="\n" if $cookies;
   $cookies.="Set-Cookie: last_hexview=$gpc->{hexview}; expires=$cookie_exp";
  }
  if (exists $gpc->{nohighlight_c}) {
   $cookies.="\n" if $cookies;
   $cookies.="Set-Cookie: last_nohighlight_c=$gpc->{nohighlight_c}; expires=$cookie_exp";
  }
  ($JavaScript)=();
  if ($ShowTooltipsIP || $ShowTooltipsHost || $ShowTooltipsEmail) {
   $JavaScript.=<<EOT;
  <script type=\"text/javascript\" src=\"get?file=images/rslite.js\"></script>
  <script type=\"text/javascript\" src=\"get?file=images/tooltip.js\"></script>
EOT
  }
  chomp($JavaScript);
  $HTMLHeaders=<<EOT;
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
<head>
  <meta http-equiv="content-type" content="application/xhtml+xml; charset=$webAdminCharset" />
  <title>ASSP (Anti SPAM SMTP Proxy)</title>
  <link rel="stylesheet" href="get?file=images/viewer.css" type="text/css" />
  <link rel="stylesheet" href="get?file=images/tooltip.css" type="text/css" />
$JavaScript
</head>
<body onLoad="window.focus();">
EOT
  $HTMLHeaders.="  <div class=\"tooltip_pop\" id=\"tooltip_pop\" onMouseOver=\"selectElement(this)\" onClick=\"selectElement(this);\"></div>\n" if $ShowTooltipsIP || $ShowTooltipsHost || $ShowTooltipsEmail;
  chomp($HTMLHeaders);
  addTooltips($s,$gpc->{nohighlight_c}) unless $gpc->{hexview};
  return <<EOT;
$HTTPHeaderOK
$cookies
$HTMLHeaderDTDStrict
$HTMLHeaders
  <div class="content">
    <h2>ASSP File Viewer</h2>
    <br />
    <form action="" method="get">
      <table class="textBox" style="width: 99%;">
        <tr>
          <td class="noBorder" align="right">
            <input type="text" name="search" value="$pat" size="30"/>
            <input type="submit" value="Search" />
          </td>
          <td class="noBorder">
            <input type="hidden" name="collection" value="$gpc->{collection}">
            <input type="hidden" name="file" value="$gpc->{file}">
            <input type="hidden" name="hexview" value="$gpc->{hexview}">
            <input type="checkbox" name="hexview_checkbox"${\($gpc->{hexview} ? ' checked="checked" ' : ' ')}value='1' onclick="this.form['hexview'].value=this.checked ? '1' : '0';"/>hexadecimal view<br />
            <input type="hidden" name="nohighlight_c" value="$gpc->{nohighlight_c}">
            <input type="checkbox" name="nohighlight_c_checkbox"${\($gpc->{nohighlight_c} ? ' checked="checked" ' : ' ')}value='1' onclick="this.form['nohighlight_c'].value=this.checked ? '1' : '0';"/>disable&nbsp;highlighting
          </td>
        </tr>
      </table>
    </form>
    <br />
    <div class="log">
$res
<pre>$s</pre>
    </div>
    <table class="textBox" style="width: 99%;">
      <tr>
        <td class="noBorder" align="left">
          <form action="/analyze" method="post" target="main" onsubmit="if (window.opener && !window.opener.closed) { window.opener.focus(); }">
            <input type="hidden" name="collection" value="$coll">
            <input type="hidden" name="file" value="$fil">
            <input type="submit" value="Analyze">
          </form>
        </td>
        <td class="noBorder" align="left">
          <form action="/simulate" method="post" target="main" onsubmit="if (window.opener && !window.opener.closed) { window.opener.focus(); }">
            <input type="hidden" name="collection" value="$coll">
            <input type="hidden" name="file" value="$fil">
            <input type="hidden" name="B1" value="detect">
            <input type="submit" value="Simulate">
          </form>
        </td>
        <td class="noBorder" align="right">
          <form action="/corpus" method="post" target="main" onsubmit="if (window.opener && !window.opener.closed) { window.opener.focus(); setTimeout('window.close()',1000); }">
            <input type="hidden" name="search" value="$pat">
            <input type="hidden" name="items[]" value="$coll|$fil">
            <select size="1" name="action">
$sel_act_html
            </select>
            <input type="submit" value="Execute">
          </form>
        </td>
      </tr>
    </table>
  </div>
$HTMLFooters
</body>
</html>
EOT
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub webEdit {
 my ($http,$gpc);
 my ($note,$s1,$s2,$s3,$fil,$JavaScript,$HTMLHeaders);
 my $sref=$Tasks{$CurTaskID}->{webEdit}||=[sub{
  ($http,$gpc)=@_;
 },sub{&jump;
  $note=$gpc->{func} eq '1' ? '<div class="note">
 File should have one entry per line; anything on a line following a numbersign (#) is ignored (a comment).
  Whitespace at the beginning or end of the line is ignored.
 </div>' : $gpc->{func} eq '2' ? '<div class="note">
 First line specifies text that appears in the subject of report message.
 The remaining lines are the report message body.
 </div>' : $gpc->{func} eq '3' ? '<div class="note">
 ASSP configuration file can be imported/exported from the other installation.
 </div>' : '';
  ($s1,$s2,$s3)=();
  $fil=$gpc->{file};
  if ($fil=~/\.\./) {
   mlog(0,"file path not allowed while editing file '$fil'");
   $s2.='<div class="text"><span class="negative">Access denied</span></div>';
  } else {
   $fil="$base/$fil" if $fil!~/^\Q$base\E/i;
   if ($gpc->{B1}=~/delete/i) {
    backupFile($fil);
   } else {
    if (defined($gpc->{contents})) {
     $s1=$gpc->{contents};
     $s1=~s/\r?\n|\r/\n/g; # make line terminators uniform
     $s1=decodeHTMLEntities($s1);
     backupFile($fil);
     if (open(F,">$fil")) {
      print F $s1;
      close F;
      $s2='<div class="text"><span class="positive">File saved successfully</span></div>';
      optionFilesReload() if $gpc->{func} eq '1';
      configReload() if $gpc->{func} eq '3';
     } else {
      mlog(0,"failed to open file for writing '$fil': $!");
      $s2='<div class="text"><span class="negative">'.ucfirst($!).'</span></div>';
     }
    }
   }
   if (open(F,"<$fil")) {
    local $/;
    $s1=<F>;
    $s1=~s/\r?\n|\r/\n/g; # make line terminators uniform
    $s1=encodeHTMLEntities($s1);
    close F;
   } elsif ($gpc->{B1}!~/delete/i) {
    mlog(0,"failed to open file for reading '$fil': $!");
    $s2='<div class="text"><span class="negative">'.ucfirst($!).'</span></div>';
   }
   if (-e $fil) {
    if ($gpc->{func} eq '3') {
     $s3='<input type="submit" name="B1" value="Save changes" />';
    } else {
     $s3='<input type="submit" name="B1" value="Save changes" />&nbsp;
          <input type="submit" name="B1" value="Delete file" />';
    }
   } else {
    $s2='<div class="text"><span class="positive">File deleted</span></div>' if $gpc->{B1}=~/delete/i;
    if ($gpc->{func} eq '3') {
     $s3='<input type="submit" name="B1" value="Save changes" />';
    } else {
     $s3='<input type="submit" name="B1" value="Save changes" />&nbsp;
          <input type="submit" name="B1" value="Delete file" disabled="disabled" />';
    }
   }
  }
  ($JavaScript)=(); # empty
  $HTMLHeaders=<<EOT;
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
<head>
  <meta http-equiv="content-type" content="application/xhtml+xml; charset=$webAdminCharset" />
  <title>ASSP (Anti SPAM SMTP Proxy)</title>
  <link rel="stylesheet" href="get?file=images/editor.css" type="text/css" />
$JavaScript
</head>
<body>
EOT
  chomp($HTMLHeaders);
  return <<EOT;
$HTTPHeaderOK
$HTMLHeaderDTDStrict
$HTMLHeaders
  <div class="content">
    <h2>ASSP File Editor</h2>
    $s2
    <form action="" method="post">
      <table class="textBox" style="width: 99%;">
        <tr>
          <td class="noBorder" align="center">
            Contents of the $fil file:<br />
            <textarea name="contents" rows="10" cols="64" wrap="off">$s1</textarea>
          </td>
        </tr>
        <tr>
          <td class="noBorder" align="center">
            $s3
          </td>
        </tr>
      </table>
    </form>
    $note
  </div>
$HTMLFooters
</body>
</html>
EOT
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub configRender {
 my ($http,$gpc)=@_;
 my $html;
 my $counter=0;
 %ConfigChanged=();
 foreach my $c (@Config) {
  my @tmp=@{$c};
  if (@tmp==5) {
   $html.=$c->[3]->(@tmp,"setupItem$counter");
   $counter++;
  } else {
   $html.=$c->[3]->(@tmp,$http,$gpc);
  }
 }
 chomp($html);
 return $html;
}

sub webConfig {
 my ($http,$gpc);
 my ($r,$quit);
 my $sref=$Tasks{$CurTaskID}->{webConfig}||=[sub{
  ($http,$gpc)=@_;
 },sub{&jump;
  $r=configRender($http,$gpc);
  if (keys %ConfigChanged) {
   configSave();
   webRender();
   openDatabases();
   newTask(taskInitAv(),'NORM',0,'M') if $ConfigChanged{AvDbs} && !$AvUseClamAV && $AvDbs;
   # re-render config if ShowNews changed
   $r=configRender($http,$gpc) if $ConfigChanged{ShowNews};
  }
  ($quit)=();
#  unless ($AsAService) {
#   $quit=<<EOT;
#    <form action="quit" method="post">
#    <table class="textBox" style="width: 99%;">
#      <tr><td class="noBorder" align="center">Panic button:</td></tr>
#      <tr><td class="noBorder" align="center"><input type="submit" value="Terminate ASSP now!" /></td></tr>
#    </table>
#    </form>
#EOT
#   chomp($quit);
#  }
  return <<EOT;
$HTTPHeaderOK
$HTMLHeaderDTDStrict
$HTMLHeaders
  <div class="content">
    <h2>ASSP Configuration</h2>
    <form action="" method="post">
      <div>
$r
      </div>
      <div class="rightButton">
        <input type="button" value="Edit Configuration" onClick="popFileEditor('assp.cfg',3);">
        <input name="theButton" type="submit" value="Apply Changes" />
      </div>
      <div class="note">
        Note: To revert an item to its default value put a single question mark (?) in the field.<br /><br />
        Items marked with an asterisk (*) accept a list separated by | or you can specify a file to read the list from
        this way: <span class="positive">file:c:/assp/data/lists/filename.txt</span> or
        <span class="positive">file:data/lists/filename.txt</span> (relative to ASSP directory base, the preferred method).<br /><br />
        Files should have one entry per line; anything on a line following a numbersign (#) is ignored (a comment).
        Whitespace at the beginning or end of the line is ignored, too.<br /><br />
        IP address lists can use CIDR notation (a.b.c.d/n) if module <a href="http://search.cpan.org/dist/Net-IP-Match-Regexp/" rel="external">Net::IP::Match::Regexp</a>
        is installed. An additional textual description of particular address/range may be included and it will be logged. It is possible to use directly lists
        such as <a href="http://www.okean.com/sinokoreacidr.txt" rel="external">Chinese/Korean IP blocks combined</a>.
      </div>
    </form>
$quit
  </div>
$HTMLFooters
  <script type="text/javascript">
  <!--
    expand(0,0);
    string=new String(document.location);
    string=string.substr(string.indexOf('#')+1);
    if (document.forms[0].length) {
      for(i=0; i<document.forms[0].elements.length; i++) {
        if (string==document.forms[0].elements[i].name) {
          document.forms[0].elements[i].focus();
        }
      }
    }
  // -->
  </script>
</body>
</html>
EOT
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub webDonations {
 my ($http,$gpc);
 my $sref=$Tasks{$CurTaskID}->{webDonations}||=[sub{
  ($http,$gpc)=@_;
 },sub{&jump;
  return <<EOT;
$HTTPHeaderOK
$HTMLHeaderDTDStrict
$HTMLHeaders
  <div class="content">
    <h2>ASSP Donations</h2>
    <div class="note">
      ASSP is here thanks to the following people, please feel free to donate to support the ASSP project.
    </div>
    <br />
    <table style="width: 99%;" class="textBox">
      <tr>
        <td class="underline">John Hanna the founder and developer of ASSP up to version 1.0.12</td>
        <td class="underline"><a href="https://www.paypal.com/xclick/business=johnhanna77%40yahoo.com&amp;item_name=Support+ASSP&amp;item_number=assp&amp;no_note=1&amp;tax=0&amp;currency_code=USD" rel="external">Donate</a></td>
      </tr>
      <tr>
        <td class="underline">AJ the designer behind ASSP's web interface &amp; site.</td>
        <td class="underline">&nbsp;</td>
      </tr>
      <tr>
        <td class="underline">John Calvi the developer of ASSP from version 1.0.12.</td>
        <td class="underline"><a href="https://www.paypal.com/xclick/business=jcalvi%40lewis.com.au&amp;item_name=Support+ASSP&amp;item_number=assp&amp;no_note=1&amp;tax=0&amp;currency_code=USD" rel="external">Donate</a></td>
      </tr>
      <tr>
        <td class="underline">Robert Orso the developer of ASSP's LDAP functions.</td>
        <td class="underline"><a href="https://www.paypal.com/xclick/business=ro%40astronomie.at&amp;item_name=Support+ASSP&amp;item_number=assp&amp;no_note=1&amp;tax=0&amp;currency_code=USD" rel="external">Donate</a></td>
      </tr>
      <tr>
        <td>&nbsp;</td>
        <td></td>
      </tr>
      <tr>
        <td colspan="2">
          <div class="note">
            Special thanks go to......<br />
            &nbsp;&nbsp;  Nigel Barling for his contributions to SPF &amp; RBL.<br />
            &nbsp;&nbsp;  Mark Pizzolato for his contributions to SMTP Session Limits.<br />
            &nbsp;&nbsp;  Przemek Czerkas for his contributions to SRS, Delaying, Searches, URIBL, RateLimit,<br />
            &nbsp;&nbsp;&nbsp;&nbsp;  Corpus Viewer, Simulator.<br />
            &nbsp;&nbsp;  Fritz Borgstedt for his contributions to HELO and Sender Validation.<br />
          </div>
        </td>
      </tr>
    </table>
  </div>
$HTMLFooters
</body>
</html>
EOT
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub webGetFile {
 my ($http,$gpc);
 my ($fil,$mtime,$s,$ct,$k,$v);
 my $sref=$Tasks{$CurTaskID}->{webGetFile}||=[sub{
  ($http,$gpc)=@_;
 },sub{&jump;
  $fil=$gpc->{file};
  if ($fil=~/\.\./) {
   mlog(0,"file path not allowed while getting file '$fil'");
   return <<EOT;
HTTP/1.0 403 Forbidden
Content-type: text/html

<html>
<body>
  <h1>Forbidden</h1>
</body>
</html>
EOT
  }
  $fil="$base/$fil" if $fil!~/^\Q$base\E/i;
  if (-e $fil) {
   ($mtime)=();
   if (defined($mtime=$http->{'if-modified-since'})) {
    if (defined($mtime=HTTPStrToTime($mtime))) {
     if ($mtime>=[stat($fil)]->[9]) {
      return <<EOT;
HTTP/1.0 304 Not Modified
Content-type: text/html

<html>
<body>
  <h1>Not Modified</h1>
</body>
</html>
EOT
     }
    }
   }
   if (open(F,"<$fil")) {
    binmode F;
    local $/;
    $s=<F>;
    close F;
    %mimeTypes=('log|txt|pl' => 'text/plain',
                'htm|html' => 'text/html',
                'css' => 'text/css',
                'bmp' => 'image/bmp',
                'gif' => 'image/gif',
                'jpg|jpeg' => 'image/jpeg',
                'png' => 'image/png',
                'zip' => 'application/zip',
                'sh' => 'application/x-sh',
                'gz|gzip' => 'application/x-gzip',
                'exe' => 'application/octet-stream',
                'js' => 'application/x-javascript');
    $ct='text/plain'; # default content-type
    while (($k,$v)=each(%mimeTypes)) {
     if ($fil=~/\.(\Q$k\E)$/i) {
      $ct=$v;
      last;
     }
    }
    $mtime=[stat($fil)]->[9];
    $mtime=gmtime($mtime);
    $mtime=~s/(...) (...) +(\d+) (........) (....)/$1, $3 $2 $5 $4 GMT/;
    return <<EOT;
HTTP/1.0 200 OK
Content-type: $ct
Last-Modified: $mtime

$s
EOT
   }
  }
  mlog(0,"failed to open file for reading '$fil': $!");
  return <<EOT;
HTTP/1.0 404 Not Found
Content-type: text/html

<html>
<body>
  <h1>Not found</h1>
</body>
</html>
EOT
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub webTooltip {
 my ($http,$gpc);
 my ($param,$data,$s,@s,$res,$packet,@answer,$a);
 my $sref=$Tasks{$CurTaskID}->{webTooltip}||=[sub{
  ($http,$gpc)=@_;
 },sub{&jump;
  ($param,$data)=split(';',$gpc->{p});
  ($s)=();
  if ($param==1) {
   # handle email addresses
   (@s)=();
   push(@s,localMailDomain($data) ? 'local' : 'non-local');
   push(@s,'whitelisted') if $Whitelist{lc $data};
   push(@s,'redlisted') if $Redlist{lc $data};
   push(@s,'blacklisted') if $blackListedDomains && ($data=~$BLDRE1);
   $s='Email address: '.join(', ',@s);
   $s=encodeHTMLEntities($s);
  } elsif ($param==2 || $param==3) {
   # handle IP addresses & host names
   if ($CanUseDNS) {
    $res=Net::DNS::Resolver->new(retrans=>1, retry=>1);
    # instant lookup, $res->bgsend() is much slower
    if ($packet=$res->search($data)) {
     @answer=$packet->answer;
     foreach $a (@answer) {
      $s.='<br>' if $s;
      $s.=$a->rdatastr;
      $s=~s/\.$//;
     }
    }
    $s||=($param==2 ? 'r' : '').'DNS not set ('.$res->errorstring.')';
   } else {
    $s='Net::DNS not installed, cannot resolve';
   }
  } else {
   $s='Invalid parameter';
  }
  return <<EOT;
HTTP/1.0 200 OK
Content-type: text/html
Set-Cookie: RSLite=$s;

<html>
<body>
  <h1>$s</h1>
</body>
</html>
EOT
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub webDocs {
 my ($http,$gpc);
 my $sref=$Tasks{$CurTaskID}->{webDocs}||=[sub{
  ($http,$gpc)=@_;
 },sub{&jump;
  return <<EOT;
$HTTPHeaderOK
$HTMLHeaderDTDStrict
$HTMLHeaders
  <div class="content">
    <h2>ASSP Documentation</h2>
    <div class="note">
      Here you'll find documentation (partially outdated) for the ASSP project.
    </div>
    <br />
    <table style="width: 99%;" class="textBox">
      <tr>
        <td><a href="get?file=docs/ASSP%20Documentation.htm" rel="external">ASSP Documentation</a></td>
      </tr>
      <tr>
        <td><a href="get?file=docs/Regular%20Expression%20Tutorial.htm" rel="external">Regular Expression Tutorial</a></td>
      </tr>
      <tr>
        <td><a href="get?file=docs/changelog.txt" rel="external">Changelog</a></td>
      </tr>
      <tr>
        <td><a href="http://www.magicvillage.de/~Fritz_Borgstedt/assp/" rel="external">Fritz Borgstedt ASSP site</a></td>
      </tr>
      <tr>
        <td><a href="http://www.pointdee.co.uk/assp-wiki/" rel="external">Wiki</a></td>
      </tr>
      <tr>
        <td>&nbsp;</td>
      </tr>
    </table>
  </div>
$HTMLFooters
</body>
</html>
EOT
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub webShutdown {
 my ($http,$gpc);
 my $sref=$Tasks{$CurTaskID}->{webShutdown}||=[sub{
  ($http,$gpc)=@_;
 },sub{&jump;
  return <<EOT;
$HTTPHeaderOK
$HTMLHeaderDTDTransitional
$HTMLHeaders
  <div class="content">
    <h2>ASSP Shutdown/Restart</h2>
    <div class="note">
      Note: It's possible to restart, if ASSP runs as a service or in a script that restarts it after it stops,
      otherwise this function can only shut ASSP down. In either case, shutdown is clean -- SMTP sessions are not
      interrupted.
    </div>
    <br />
    <table style="background-color: white; border-width: 0px; width: 100%">
      <tr>
        <td style="background-color: white; padding: 0px;">
          <iframe src="/shutdown_frame" width="100%" height="260" frameborder="0" marginwidth="0" marginheight="0" scrolling="no"></iframe>
        </td>
      </tr>
    </table>
  </div>
$HTMLFooters
</body>
</html>
EOT
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub webShutdownFrame {
 my ($http,$gpc);
 my ($action,$s1,$s2,$query,$refresh,$shutdownDelay,$timerJS,$sessCnt,$fh,$m,$indent,$client,$from,$to);
 my $sref=$Tasks{$CurTaskID}->{webShutdownFrame}||=[sub{
  ($http,$gpc)=@_;
 },sub{&jump;
  $action=$gpc->{action};
  ($s1,$s2,$query,$refresh)=();
  $shutdownDelay=2;
  $timerJS='
<script type="text/javascript">
  var ns=(navigator.appName.indexOf("Netscape")!=-1);
  var timerVal=parseInt(ns ? document.getElementById("myTimer1").childNodes[0].nodeValue : myTimer1.innerText);
  function countDown() {
    if (isNaN(timerVal)==0 && timerVal>=0) {
      if (ns) {
        document.getElementById("myTimer1").childNodes[0].nodeValue=timerVal--;
      } else {
        myTimer1.innerText=timerVal--;
      }
      setTimeout("countDown()",1000);
    }
  }
  countDown();
</script>';
  $sessCnt=keys %SMTPSessions;
  if ($action=~/abort/i) {
   mlog(0,"shutdown/restart process aborted per admin request; SMTP session count:$sessCnt");
   $shuttingDown=0;
   $refresh=3;
   $s1='Shutdown/restart request aborted.';
   $s2='<input type="submit" name="action" value="  Proceed  " disabled="disabled" />&nbsp;
        <input type="submit" name="action" value="    Abort    " disabled="disabled" />';
   $doShutdown=0;
   $query='?nocache';
  } elsif ($action=~/proceed/i || $shuttingDown) {
   mlog(0,"shutdown/restart process initiated per admin request; SMTP session count:$sessCnt") if $action=~/proceed/i;
   $shuttingDown=1;
   $refresh=$sessCnt>0 ? 2 : !$AvUseClamAV && $AvDbs ? 90 : 40;
   $s1=$sessCnt>0 ? 'Please wait for '. needEs($sessCnt,' SMTP session','s') .' to finish ...' : "Shutdown/restart in progress, please wait ... <span id=\"myTimer1\">$refresh</span>s$timerJS";
   $s2='<input type="submit" name="action" value="  Proceed  " disabled="disabled" />&nbsp;
        <input type="submit" name="action" value="    Abort    "'.($sessCnt>0 ? '' : ' disabled="disabled"').' />';
   $doShutdown=$sessCnt>0 ? 0 : time+$shutdownDelay;
   $query=$sessCnt>0 ? '?nocache' : '?action=Success';
  } elsif ($action=~/success/i) {
   $refresh=3;
   $s1='ASSP restarted successfully.';
   $s2='<input type="submit" name="action" value="  Proceed  " disabled="disabled" />&nbsp;
        <input type="submit" name="action" value="    Abort    " disabled="disabled" />';
   $doShutdown=0;
   $query='?nocache';
  } else {
   $refresh=2;
   $s1=$sessCnt>0 ? ($sessCnt>1 ? 'There are ' : 'There is '). needEs($sessCnt,' SMTP session','s') .' active.' : 'There are no active SMTP sessions.';
   $s1.='<pre>';
   foreach $fh (keys %SMTPSessions) {
    $m=localtime(int($SMTPSessions{$fh}->{stime}));
    $m=~s/^... (...) +(\d+) (\S+) ..(..)/$1-$2-$4 $3 /;
    $indent=' ' x length($m); # calculate indent
    ($client,$from)=();
    $client="$SMTPSessions{$fh}->{client} ($Con{$fh}->{helo}) " if $Con{$fh}->{inenvelope};
    $from="<$Con{$fh}->{mailfrom}> " if $Con{$fh}->{inmailfrom};
    ($to)=$Con{$fh}->{rcpt}=~/(\S+)/;
    $to="to: $to " if $to;
    $m.="$client$from$to";
    $m.="\n";
    $m=encodeHTMLEntities($m);
    $m=logWrap($m,$MaillogTailWrapColumn,$indent) if $MaillogTailWrapColumn>0;
    $s1.=$m;
   }
   $s1.='</pre>';
   $s2='<input type="submit" name="action" value="  Proceed  " />&nbsp;
        <input type="submit" name="action" value="    Abort    " disabled="disabled" />';
   $doShutdown=0;
   $query='?nocache';
  }
  addTooltips($s1);
  return <<EOT;
$HTTPHeaderOK
$HTMLHeaderDTDStrict
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
<head>
  <meta http-equiv="content-type" content="application/xhtml+xml; charset=$webAdminCharset" />
  <meta http-equiv="refresh" content="$refresh;url=/shutdown_frame$query" />
  <title>ASSP (Anti SPAM SMTP Proxy)</title>
  <link rel="stylesheet" href="get?file=images/shutdown.css" type="text/css" />
</head>
<body>
  <div class="content">
    <form action="" method="get">
      <table class="textBox">
        <tr>
          <td class="noBorder">
            <p style="padding: 2px; background-color: #e9e9e9">
              $s1
            </p>
            <br />
          </td>
        </tr>
        <tr>
          <td class="noBorder" align="center">
            $s2<br />
            &nbsp;
          </td>
        </tr>
      </table>
    </form>
$s
  </div>
</body>
</html>
EOT
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub webStats {
 my ($http,$gpc);
 my ($t,@items,$i,%tots,$upt,$upt2,$uptime,$uptime2,$mpd,$mpd2,$pct,$pct2,$sessCnt);
 my ($prbytesClientSMTP,$prbytesServerSMTP,$prbytesRelaySMTP,$prbytesClientSMTP2,$prbytesServerSMTP2,$prbytesRelaySMTP2);
 my ($drbytesClientSMTP,$drbytesServerSMTP,$drbytesRelaySMTP,$drbytesClientSMTP2,$drbytesServerSMTP2,$drbytesRelaySMTP2);
 my ($pwbytesClientSMTP,$pwbytesServerSMTP,$pwbytesRelaySMTP,$pwbytesClientSMTP2,$pwbytesServerSMTP2,$pwbytesRelaySMTP2);
 my ($dwbytesClientSMTP,$dwbytesServerSMTP,$dwbytesRelaySMTP,$dwbytesClientSMTP2,$dwbytesServerSMTP2,$dwbytesRelaySMTP2);
 my ($rbytesClientSMTP,$rbytesServerSMTP,$rbytesRelaySMTP,$rbytesClientSMTP2,$rbytesServerSMTP2,$rbytesRelaySMTP2);
 my ($wbytesClientSMTP,$wbytesServerSMTP,$wbytesRelaySMTP,$wbytesClientSMTP2,$wbytesServerSMTP2,$wbytesRelaySMTP2);
 my ($prbytesSMTP,$pwbytesSMTP,$prbytesSMTP2,$pwbytesSMTP2,$drbytesSMTP,$dwbytesSMTP);
 my ($drbytesSMTP2,$dwbytesSMTP2,$rbytesSMTP,$wbytesSMTP,$rbytesSMTP2,$wbytesSMTP2);
 my ($prbytesMeanHam,$prbytesMeanHam2,$prbytesMeanPassedSpam,$prbytesMeanPassedSpam2,$prbytesMeanBlockedSpam,$prbytesMeanBlockedSpam2);
 my ($prbytesMeanMsg,$prbytesMeanMsg2,$drbytesMeanHam,$drbytesMeanHam2,$drbytesMeanPassedSpam,$drbytesMeanPassedSpam2);
 my ($drbytesMeanBlockedSpam,$drbytesMeanBlockedSpam2,$drbytesMeanMsg,$drbytesMeanMsg2,$rbytesMeanHam,$rbytesMeanHam2);
 my ($rbytesMeanPassedSpam,$rbytesMeanPassedSpam2,$rbytesMeanBlockedSpam,$rbytesMeanBlockedSpam2,$rbytesMeanMsg,$rbytesMeanMsg2);
 my ($rtputMeanHam,$rtputMeanHam2,$rtputMeanPassedSpam,$rtputMeanPassedSpam2,$rtputMeanBlockedSpam,$rtputMeanBlockedSpam2,$rtputMeanMsg,$rtputMeanMsg2);
 my ($pdrtputMeanHam,$pdrtputMeanHam2,$pdrtputMeanPassedSpam,$pdrtputMeanPassedSpam2,$pdrtputMeanBlockedSpam,$pdrtputMeanBlockedSpam2,$pdrtputMeanMsg,$pdrtputMeanMsg2);
 my ($lBanner,$lBanner2,$lBannerHam,$lBannerHam2,$lBannerPassedSpam,$lBannerPassedSpam2,$lBannerBlockedSpam,$lBannerBlockedSpam2);
 my ($lMean,$lMean2,$lMeanHam,$lMeanHam2,$lMeanPassedSpam,$lMeanPassedSpam2,$lMeanBlockedSpam,$lMeanBlockedSpam2,$lMeanSuffix);
 my ($lminmaxMean,$lminmaxMean2,$lminmaxMeanHam,$lminmaxMeanHam2,$lminmaxMeanPassedSpam,$lminmaxMeanPassedSpam2,$lminmaxMeanBlockedSpam,$lminmaxMeanBlockedSpam2);
 my ($tActive,$tActiveM,$tActiveS,$tActiveW,$tctMean,$tctMean2,$tctMeanM,$tctMeanM2,$tctMeanS);
 my ($tctMeanS2,$tctMeanW,$tctMeanW2,$tctMeanKernel,$tctMeanKernel2,$tQueue,$tQueueHigh,$tQueueNorm);
 my ($tQueueIdle,$tQueueWait,$tQueueSuspend,$tid,$task);
 my ($cpuUsageAvg,$cpuUsageAvg2,$cpuUsageAvgKernel,$cpuUsageAvgKernel2,$cpuUsageAvgUser,$cpuUsageAvgUser2);
 my ($cpuUsageAvgM,$cpuUsageAvgM2,$cpuUsageAvgS,$cpuUsageAvgS2,$cpuUsageAvgW,$cpuUsageAvgW2);
 my ($tot_html,$mean_html,$msg_html,$traf_html,$prov_html,$tput_html,$lncy_html,$task_html,$name,$class,$value1,$value2);
 my $sref=$Tasks{$CurTaskID}->{webStats}||=[sub{
  ($http,$gpc)=@_;
 },sub{&jump;
  $t=time;
  @items=(['StatItem0','on'],
          ['StatItem1','off'],
          ['StatItem2','off'],
          ['StatItem3','off'],
          ['StatItem4','off'],
          ['StatItem5','off'],
          ['StatItem6','off'],
          ['StatItem7','off'],
          ['StatItem8','off'],
          ['StatItem9','off'],
          ['StatItem10','off'],
          ['StatItem11','off'],
          ['StatItem12','off']);
  foreach $i (@items) {
   if (!exists $gpc->{$i->[0]} && exists $gpc->{"last_$i->[0]"}) {
    $gpc->{$i->[0]}=$gpc->{"last_$i->[0]"};
   } else {
    $gpc->{$i->[0]}=$i->[1];
   }
  }
  if ($gpc->{action}=~/reset/i) {
   mlog(0,'resetting statistics per admin request');
   resetStats();
   undef %OldStats;
   $Stats{starttime}=$t;
  }
  saveStats();
  %tots=statsTotals();
  $upt=$t-$Stats{starttime};
  $upt2=$t-$AllStats{starttime};
  $uptime=formatTimeInterval($upt,0);
  $uptime2=formatTimeInterval($upt2,0);
  $mpd=sprintf("%.0f",$upt==0 ? 0 : 86400*$tots{msgProcessed}/$upt);
  $mpd2=sprintf("%.0f",$upt2==0 ? 0 : 86400*$tots{msgProcessed2}/$upt2);
  $pct=sprintf("%.1f",$tots{msgProcessed}-$Stats{locals}==0 ? 0 : 100*$tots{msgRejected}/($tots{msgProcessed}-$Stats{locals}));
  $pct2=sprintf("%.1f",$tots{msgProcessed2}-$AllStats{locals}==0 ? 0 : 100*$tots{msgRejected2}/($tots{msgProcessed2}-$AllStats{locals}));
  $sessCnt=keys %SMTPSessions;
  # bytes totalled per side of proxy
  $prbytesClientSMTP=formatDataSize($Stats{prbytesClientSMTP},1);
  $prbytesServerSMTP=formatDataSize($Stats{prbytesServerSMTP},1);
  $prbytesRelaySMTP=formatDataSize($Stats{prbytesRelaySMTP},1);
  $prbytesClientSMTP2=formatDataSize($AllStats{prbytesClientSMTP},1);
  $prbytesServerSMTP2=formatDataSize($AllStats{prbytesServerSMTP},1);
  $prbytesRelaySMTP2=formatDataSize($AllStats{prbytesRelaySMTP},1);
  $drbytesClientSMTP=formatDataSize($Stats{drbytesClientSMTP},1);
  $drbytesServerSMTP=formatDataSize($Stats{drbytesServerSMTP},1);
  $drbytesRelaySMTP=formatDataSize($Stats{drbytesRelaySMTP},1);
  $drbytesClientSMTP2=formatDataSize($AllStats{drbytesClientSMTP},1);
  $drbytesServerSMTP2=formatDataSize($AllStats{drbytesServerSMTP},1);
  $drbytesRelaySMTP2=formatDataSize($AllStats{drbytesRelaySMTP},1);
  $pwbytesClientSMTP=formatDataSize($Stats{pwbytesClientSMTP},1);
  $pwbytesServerSMTP=formatDataSize($Stats{pwbytesServerSMTP},1);
  $pwbytesRelaySMTP=formatDataSize($Stats{pwbytesRelaySMTP},1);
  $pwbytesClientSMTP2=formatDataSize($AllStats{pwbytesClientSMTP},1);
  $pwbytesServerSMTP2=formatDataSize($AllStats{pwbytesServerSMTP},1);
  $pwbytesRelaySMTP2=formatDataSize($AllStats{pwbytesRelaySMTP},1);
  $dwbytesClientSMTP=formatDataSize($Stats{dwbytesClientSMTP},1);
  $dwbytesServerSMTP=formatDataSize($Stats{dwbytesServerSMTP},1);
  $dwbytesRelaySMTP=formatDataSize($Stats{dwbytesRelaySMTP},1);
  $dwbytesClientSMTP2=formatDataSize($AllStats{dwbytesClientSMTP},1);
  $dwbytesServerSMTP2=formatDataSize($AllStats{dwbytesServerSMTP},1);
  $dwbytesRelaySMTP2=formatDataSize($AllStats{dwbytesRelaySMTP},1);
  $rbytesClientSMTP=formatDataSize($tots{rbytesClientSMTP},1);
  $rbytesServerSMTP=formatDataSize($tots{rbytesServerSMTP},1);
  $rbytesRelaySMTP=formatDataSize($tots{rbytesRelaySMTP},1);
  $rbytesClientSMTP2=formatDataSize($tots{rbytesClientSMTP2},1);
  $rbytesServerSMTP2=formatDataSize($tots{rbytesServerSMTP2},1);
  $rbytesRelaySMTP2=formatDataSize($tots{rbytesRelaySMTP2},1);
  $wbytesClientSMTP=formatDataSize($tots{wbytesClientSMTP},1);
  $wbytesServerSMTP=formatDataSize($tots{wbytesServerSMTP},1);
  $wbytesRelaySMTP=formatDataSize($tots{wbytesRelaySMTP},1);
  $wbytesClientSMTP2=formatDataSize($tots{wbytesClientSMTP2},1);
  $wbytesServerSMTP2=formatDataSize($tots{wbytesServerSMTP2},1);
  $wbytesRelaySMTP2=formatDataSize($tots{wbytesRelaySMTP2},1);
  $prbytesSMTP=formatDataSize($tots{prbytesSMTP},1);
  $pwbytesSMTP=formatDataSize($tots{pwbytesSMTP},1);
  $prbytesSMTP2=formatDataSize($tots{prbytesSMTP2},1);
  $pwbytesSMTP2=formatDataSize($tots{pwbytesSMTP2},1);
  $drbytesSMTP=formatDataSize($tots{drbytesSMTP},1);
  $dwbytesSMTP=formatDataSize($tots{dwbytesSMTP},1);
  $drbytesSMTP2=formatDataSize($tots{drbytesSMTP2},1);
  $dwbytesSMTP2=formatDataSize($tots{dwbytesSMTP2},1);
  $rbytesSMTP=formatDataSize($tots{rbytesSMTP},1);
  $wbytesSMTP=formatDataSize($tots{wbytesSMTP},1);
  $rbytesSMTP2=formatDataSize($tots{rbytesSMTP2},1);
  $wbytesSMTP2=formatDataSize($tots{wbytesSMTP2},1);
  # mean message bytes received per message class
  $prbytesMeanHam=formatDataSize($tots{msgHam}==0 ? 0 : $tots{prbytesHam}/$tots{msgHam},1);
  $prbytesMeanHam2=formatDataSize($tots{msgHam2}==0 ? 0 : $tots{prbytesHam2}/$tots{msgHam2},1);
  $prbytesMeanPassedSpam=formatDataSize($tots{msgPassedSpam}==0 ? 0 : $tots{prbytesPassedSpam}/$tots{msgPassedSpam},1);
  $prbytesMeanPassedSpam2=formatDataSize($tots{msgPassedSpam2}==0 ? 0 : $tots{prbytesPassedSpam2}/$tots{msgPassedSpam2},1);
  $prbytesMeanBlockedSpam=formatDataSize($tots{msgBlockedSpam}==0 ? 0 : $tots{prbytesBlockedSpam}/$tots{msgBlockedSpam},1);
  $prbytesMeanBlockedSpam2=formatDataSize($tots{msgBlockedSpam2}==0 ? 0 : $tots{prbytesBlockedSpam2}/$tots{msgBlockedSpam2},1);
  $prbytesMeanMsg=formatDataSize($tots{msg}==0 ? 0 : $tots{prbytesMsg}/$tots{msg},1);
  $prbytesMeanMsg2=formatDataSize($tots{msg2}==0 ? 0 : $tots{prbytesMsg2}/$tots{msg2},1);
  $drbytesMeanHam=formatDataSize($tots{msgHam}==0 ? 0 : $tots{drbytesHam}/$tots{msgHam},1);
  $drbytesMeanHam2=formatDataSize($tots{msgHam2}==0 ? 0 : $tots{drbytesHam2}/$tots{msgHam2},1);
  $drbytesMeanPassedSpam=formatDataSize($tots{msgPassedSpam}==0 ? 0 : $tots{drbytesPassedSpam}/$tots{msgPassedSpam},1);
  $drbytesMeanPassedSpam2=formatDataSize($tots{msgPassedSpam2}==0 ? 0 : $tots{drbytesPassedSpam2}/$tots{msgPassedSpam2},1);
  $drbytesMeanBlockedSpam=formatDataSize($tots{msgBlockedSpam}==0 ? 0 : $tots{drbytesBlockedSpam}/$tots{msgBlockedSpam},1);
  $drbytesMeanBlockedSpam2=formatDataSize($tots{msgBlockedSpam2}==0 ? 0 : $tots{drbytesBlockedSpam2}/$tots{msgBlockedSpam2},1);
  $drbytesMeanMsg=formatDataSize($tots{msg}==0 ? 0 : $tots{drbytesMsg}/$tots{msg},1);
  $drbytesMeanMsg2=formatDataSize($tots{msg2}==0 ? 0 : $tots{drbytesMsg2}/$tots{msg2},1);
  $rbytesMeanHam=formatDataSize($tots{msgHam}==0 ? 0 : $tots{rbytesHam}/$tots{msgHam},1);
  $rbytesMeanHam2=formatDataSize($tots{msgHam2}==0 ? 0 : $tots{rbytesHam2}/$tots{msgHam2},1);
  $rbytesMeanPassedSpam=formatDataSize($tots{msgPassedSpam}==0 ? 0 : $tots{rbytesPassedSpam}/$tots{msgPassedSpam},1);
  $rbytesMeanPassedSpam2=formatDataSize($tots{msgPassedSpam2}==0 ? 0 : $tots{rbytesPassedSpam2}/$tots{msgPassedSpam2},1);
  $rbytesMeanBlockedSpam=formatDataSize($tots{msgBlockedSpam}==0 ? 0 : $tots{rbytesBlockedSpam}/$tots{msgBlockedSpam},1);
  $rbytesMeanBlockedSpam2=formatDataSize($tots{msgBlockedSpam2}==0 ? 0 : $tots{rbytesBlockedSpam2}/$tots{msgBlockedSpam2},1);
  $rbytesMeanMsg=formatDataSize($tots{msg}==0 ? 0 : $tots{rbytesMsg}/$tots{msg},1);
  $rbytesMeanMsg2=formatDataSize($tots{msg2}==0 ? 0 : $tots{rbytesMsg2}/$tots{msg2},1);
  if ($AvailHiRes) {
   # mean throughput per message class
   $rtputMeanHam=formatDataSize($tots{rtimeHam}==0 ? 0 : $tots{rbytesHam}/$tots{rtimeHam},1).'ps';
   $rtputMeanHam2=formatDataSize($tots{rtimeHam2}==0 ? 0 : $tots{rbytesHam2}/$tots{rtimeHam2},1).'ps';
   $rtputMeanPassedSpam=formatDataSize($tots{rtimePassedSpam}==0 ? 0 : $tots{rbytesPassedSpam}/$tots{rtimePassedSpam},1).'ps';
   $rtputMeanPassedSpam2=formatDataSize($tots{rtimePassedSpam2}==0 ? 0 : $tots{rbytesPassedSpam2}/$tots{rtimePassedSpam2},1).'ps';
   $rtputMeanBlockedSpam=formatDataSize($tots{rtimeBlockedSpam}==0 ? 0 : $tots{rbytesBlockedSpam}/$tots{rtimeBlockedSpam},1).'ps';
   $rtputMeanBlockedSpam2=formatDataSize($tots{rtimeBlockedSpam2}==0 ? 0 : $tots{rbytesBlockedSpam2}/$tots{rtimeBlockedSpam2},1).'ps';
   $rtputMeanMsg=formatDataSize($tots{rtimeMsg}==0 ? 0 : $tots{rbytesMsg}/$tots{rtimeMsg},1).'ps';
   $rtputMeanMsg2=formatDataSize($tots{rtimeMsg2}==0 ? 0 : $tots{rbytesMsg2}/$tots{rtimeMsg2},1).'ps';
   $pdrtputMeanHam=' ('.formatDataSize($tots{prtimeHam}==0 ? 0 : $tots{prbytesHam}/$tots{prtimeHam},1).'ps&nbsp;/&nbsp;'.formatDataSize($tots{drtimeHam}==0 ? 0 : $tots{drbytesHam}/$tots{drtimeHam},1).'ps)';
   $pdrtputMeanHam2=' ('.formatDataSize($tots{prtimeHam2}==0 ? 0 : $tots{prbytesHam2}/$tots{prtimeHam2},1).'ps&nbsp;/&nbsp;'.formatDataSize($tots{drtimeHam2}==0 ? 0 : $tots{drbytesHam2}/$tots{drtimeHam2},1).'ps)';
   $pdrtputMeanPassedSpam=' ('.formatDataSize($tots{prtimePassedSpam}==0 ? 0 : $tots{prbytesPassedSpam}/$tots{prtimePassedSpam},1).'ps&nbsp;/&nbsp;'.formatDataSize($tots{drtimePassedSpam}==0 ? 0 : $tots{drbytesPassedSpam}/$tots{drtimePassedSpam},1).'ps)';
   $pdrtputMeanPassedSpam2=' ('.formatDataSize($tots{prtimePassedSpam2}==0 ? 0 : $tots{prbytesPassedSpam2}/$tots{prtimePassedSpam2},1).'ps&nbsp;/&nbsp;'.formatDataSize($tots{drtimePassedSpam2}==0 ? 0 : $tots{drbytesPassedSpam2}/$tots{drtimePassedSpam2},1).'ps)';
   $pdrtputMeanBlockedSpam=' ('.formatDataSize($tots{prtimeBlockedSpam}==0 ? 0 : $tots{prbytesBlockedSpam}/$tots{prtimeBlockedSpam},1).'ps&nbsp;/&nbsp;'.formatDataSize($tots{drtimeBlockedSpam}==0 ? 0 : $tots{drbytesBlockedSpam}/$tots{drtimeBlockedSpam},1).'ps)';
   $pdrtputMeanBlockedSpam2=' ('.formatDataSize($tots{prtimeBlockedSpam2}==0 ? 0 : $tots{prbytesBlockedSpam2}/$tots{prtimeBlockedSpam2},1).'ps&nbsp;/&nbsp;'.formatDataSize($tots{drtimeBlockedSpam2}==0 ? 0 : $tots{drbytesBlockedSpam2}/$tots{drtimeBlockedSpam2},1).'ps)';
   $pdrtputMeanMsg=' ('.formatDataSize($tots{prtimeMsg}==0 ? 0 : $tots{prbytesMsg}/$tots{prtimeMsg},1).'ps&nbsp;/&nbsp;'.formatDataSize($tots{drtimeMsg}==0 ? 0 : $tots{drbytesMsg}/$tots{drtimeMsg},1).'ps)';
   $pdrtputMeanMsg2=' ('.formatDataSize($tots{prtimeMsg2}==0 ? 0 : $tots{prbytesMsg2}/$tots{prtimeMsg2},1).'ps&nbsp;/&nbsp;'.formatDataSize($tots{drtimeMsg2}==0 ? 0 : $tots{drbytesMsg2}/$tots{drtimeMsg2},1).'ps)';
  } else {
   ($rtputMeanHam,$rtputMeanHam2,$rtputMeanPassedSpam,$rtputMeanPassedSpam2)=('n/a')x4;
   ($rtputMeanBlockedSpam,$rtputMeanBlockedSpam2,$rtputMeanMsg,$rtputMeanMsg2)=('n/a')x4;
   ($pdrtputMeanHam,$pdrtputMeanHam2,$pdrtputMeanPassedSpam,$pdrtputMeanPassedSpam2)=();
   ($pdrtputMeanBlockedSpam,$pdrtputMeanBlockedSpam2,$pdrtputMeanMsg,$pdrtputMeanMsg2)=();
  }
  if ($AvailHiRes) {
   # banner latency per message class
   $lBanner=formatTimeInterval($tots{msg}==0 ? 0 : $tots{lbanner}/$tots{msg},1).' ttfb / ';
   $lBanner2=formatTimeInterval($tots{msg2}==0 ? 0 : $tots{lbanner2}/$tots{msg2},1).' ttfb / ';
   $lBannerHam=formatTimeInterval($tots{msgHam}==0 ? 0 : $tots{lbannerHam}/$tots{msgHam},1).' ttfb / ';
   $lBannerHam2=formatTimeInterval($tots{msgHam2}==0 ? 0 : $tots{lbannerHam2}/$tots{msgHam2},1).' ttfb / ';
   $lBannerPassedSpam=formatTimeInterval($tots{msgPassedSpam}==0 ? 0 : $tots{lbannerPassedSpam}/$tots{msgPassedSpam},1).' ttfb / ';
   $lBannerPassedSpam2=formatTimeInterval($tots{msgPassedSpam2}==0 ? 0 : $tots{lbannerPassedSpam2}/$tots{msgPassedSpam2},1).' ttfb / ';
   $lBannerBlockedSpam=formatTimeInterval($tots{msgBlockedSpam}==0 ? 0 : $tots{lbannerBlockedSpam}/$tots{msgBlockedSpam},1).' ttfb / ';
   $lBannerBlockedSpam2=formatTimeInterval($tots{msgBlockedSpam2}==0 ? 0 : $tots{lbannerBlockedSpam2}/$tots{msgBlockedSpam2},1).' ttfb / ';
   # mean latency per message class
   $lMean=formatTimeInterval($tots{msg}==0 ? 0 : ($tots{lmin}+$tots{lmax})/(2*$tots{msg}),1);
   $lMean2=formatTimeInterval($tots{msg2}==0 ? 0 : ($tots{lmin2}+$tots{lmax2})/(2*$tots{msg2}),1);
   $lMeanHam=formatTimeInterval($tots{msgHam}==0 ? 0 : ($tots{lminHam}+$tots{lmaxHam})/(2*$tots{msgHam}),1);
   $lMeanHam2=formatTimeInterval($tots{msgHam2}==0 ? 0 : ($tots{lminHam2}+$tots{lmaxHam2})/(2*$tots{msgHam2}),1);
   $lMeanPassedSpam=formatTimeInterval($tots{msgPassedSpam}==0 ? 0 : ($tots{lminPassedSpam}+$tots{lmaxPassedSpam})/(2*$tots{msgPassedSpam}),1);
   $lMeanPassedSpam2=formatTimeInterval($tots{msgPassedSpam2}==0 ? 0 : ($tots{lminPassedSpam2}+$tots{lmaxPassedSpam2})/(2*$tots{msgPassedSpam2}),1);
   $lMeanBlockedSpam=formatTimeInterval($tots{msgBlockedSpam}==0 ? 0 : ($tots{lminBlockedSpam}+$tots{lmaxBlockedSpam})/(2*$tots{msgBlockedSpam}),1);
   $lMeanBlockedSpam2=formatTimeInterval($tots{msgBlockedSpam2}==0 ? 0 : ($tots{lminBlockedSpam2}+$tots{lmaxBlockedSpam2})/(2*$tots{msgBlockedSpam2}),1);
   $lminmaxMean=' ('.formatTimeInterval($tots{msg}==0 ? 0 : $tots{lmin}/$tots{msg},1).'&nbsp;-&nbsp;'.formatTimeInterval($tots{msg}==0 ? 0 : $tots{lmax}/$tots{msg},1).')';
   $lminmaxMean2=' ('.formatTimeInterval($tots{msg2}==0 ? 0 : $tots{lmin2}/$tots{msg2},1).'&nbsp;-&nbsp;'.formatTimeInterval($tots{msg2}==0 ? 0 : $tots{lmax2}/$tots{msg2},1).')';
   $lminmaxMeanHam=' ('.formatTimeInterval($tots{msgHam}==0 ? 0 : $tots{lminHam}/$tots{msgHam},1).'&nbsp;-&nbsp;'.formatTimeInterval($tots{msgHam}==0 ? 0 : $tots{lmaxHam}/$tots{msgHam},1).')';
   $lminmaxMeanHam2=' ('.formatTimeInterval($tots{msgHam2}==0 ? 0 : $tots{lminHam2}/$tots{msgHam2},1).'&nbsp;-&nbsp;'.formatTimeInterval($tots{msgHam2}==0 ? 0 : $tots{lmaxHam2}/$tots{msgHam2},1).')';
   $lminmaxMeanPassedSpam=' ('.formatTimeInterval($tots{msgPassedSpam}==0 ? 0 : $tots{lminPassedSpam}/$tots{msgPassedSpam},1).'&nbsp;-&nbsp;'.formatTimeInterval($tots{msgPassedSpam}==0 ? 0 : $tots{lmaxPassedSpam}/$tots{msgPassedSpam},1).')';
   $lminmaxMeanPassedSpam2=' ('.formatTimeInterval($tots{msgPassedSpam2}==0 ? 0 : $tots{lminPassedSpam2}/$tots{msgPassedSpam2},1).'&nbsp;-&nbsp;'.formatTimeInterval($tots{msgPassedSpam2}==0 ? 0 : $tots{lmaxPassedSpam2}/$tots{msgPassedSpam2},1).')';
   $lminmaxMeanBlockedSpam=' ('.formatTimeInterval($tots{msgBlockedSpam}==0 ? 0 : $tots{lminBlockedSpam}/$tots{msgBlockedSpam},1).'&nbsp;-&nbsp;'.formatTimeInterval($tots{msgBlockedSpam}==0 ? 0 : $tots{lmaxBlockedSpam}/$tots{msgBlockedSpam},1).')';
   $lminmaxMeanBlockedSpam2=' ('.formatTimeInterval($tots{msgBlockedSpam2}==0 ? 0 : $tots{lminBlockedSpam2}/$tots{msgBlockedSpam2},1).'&nbsp;-&nbsp;'.formatTimeInterval($tots{msgBlockedSpam2}==0 ? 0 : $tots{lmaxBlockedSpam2}/$tots{msgBlockedSpam2},1).')';
   $lMeanSuffix=' avg';
  } else {
   ($lBanner,$lBanner2,$lBannerHam,$lBannerHam2,$lBannerPassedSpam,$lBannerPassedSpam2,$lBannerBlockedSpam,$lBannerBlockedSpam2)=('n/a')x8;
   ($lMean,$lMean2,$lMeanHam,$lMeanHam2,$lMeanPassedSpam,$lMeanPassedSpam2,$lMeanBlockedSpam,$lMeanBlockedSpam2)=();
   ($lminmaxMean,$lminmaxMean2,$lminmaxMeanHam,$lminmaxMeanHam2)=();
   ($lminmaxMeanPassedSpam,$lminmaxMeanPassedSpam2,$lminmaxMeanBlockedSpam,$lminmaxMeanBlockedSpam2)=();
   $lMeanSuffix='';
  }
  # active tasks
  $tActive=$tots{taskCreated}-$tots{taskFinished};
  $tActiveM=$Stats{taskCreatedM}-$Stats{taskFinishedM};
  $tActiveS=$Stats{taskCreatedS}-$Stats{taskFinishedS};
  $tActiveW=$Stats{taskCreatedW}-$Stats{taskFinishedW};
  if ($AvailHiRes) {
   # task call time
   $tctMean=formatTimeInterval($tots{taskCalls}==0 ? 0 : $Stats{taskTimeUser}/$tots{taskCalls},1).' avg';
   $tctMean2=formatTimeInterval($tots{taskCalls2}==0 ? 0 : $AllStats{taskTimeUser}/$tots{taskCalls2},1).' avg';
   $tctMeanM=formatTimeInterval($Stats{taskCallsM}==0 ? 0 : $Stats{taskTimeM}/$Stats{taskCallsM},1).' avg';
   $tctMeanM2=formatTimeInterval($AllStats{taskCallsM}==0 ? 0 : $AllStats{taskTimeM}/$AllStats{taskCallsM},1).' avg';
   $tctMeanS=formatTimeInterval($Stats{taskCallsS}==0 ? 0 : $Stats{taskTimeS}/$Stats{taskCallsS},1).' avg';
   $tctMeanS2=formatTimeInterval($AllStats{taskCallsS}==0 ? 0 : $AllStats{taskTimeS}/$AllStats{taskCallsS},1).' avg';
   $tctMeanW=formatTimeInterval($Stats{taskCallsW}==0 ? 0 : $Stats{taskTimeW}/$Stats{taskCallsW},1).' avg';
   $tctMeanW2=formatTimeInterval($AllStats{taskCallsW}==0 ? 0 : $AllStats{taskTimeW}/$AllStats{taskCallsW},1).' avg';
   $tctMeanKernel=formatTimeInterval($Stats{taskCallsKernel}==0 ? 0 : $Stats{taskTimeKernel}/$Stats{taskCallsKernel},1).' avg';
   $tctMeanKernel2=formatTimeInterval($AllStats{taskCallsKernel}==0 ? 0 : $AllStats{taskTimeKernel}/$AllStats{taskCallsKernel},1).' avg';
   $tctminmaxMean=' ('.formatTimeInterval($Stats{taskMinTimeUser},1).'&nbsp;-&nbsp;'.formatTimeInterval($Stats{taskMaxTimeUser},1).')';
   $tctminmaxMean2=' ('.formatTimeInterval($AllStats{taskMinTimeUser},1).'&nbsp;-&nbsp;'.formatTimeInterval($AllStats{taskMaxTimeUser},1).')';
   $tctminmaxMeanM=' ('.formatTimeInterval($Stats{taskMinTimeM},1).'&nbsp;-&nbsp;'.formatTimeInterval($Stats{taskMaxTimeM},1).')';
   $tctminmaxMeanM2=' ('.formatTimeInterval($AllStats{taskMinTimeM},1).'&nbsp;-&nbsp;'.formatTimeInterval($AllStats{taskMaxTimeM},1).')';
   $tctminmaxMeanS=' ('.formatTimeInterval($Stats{taskMinTimeS},1).'&nbsp;-&nbsp;'.formatTimeInterval($Stats{taskMaxTimeS},1).')';
   $tctminmaxMeanS2=' ('.formatTimeInterval($AllStats{taskMinTimeS},1).'&nbsp;-&nbsp;'.formatTimeInterval($AllStats{taskMaxTimeS},1).')';
   $tctminmaxMeanW=' ('.formatTimeInterval($Stats{taskMinTimeW},1).'&nbsp;-&nbsp;'.formatTimeInterval($Stats{taskMaxTimeW},1).')';
   $tctminmaxMeanW2=' ('.formatTimeInterval($AllStats{taskMinTimeW},1).'&nbsp;-&nbsp;'.formatTimeInterval($AllStats{taskMaxTimeW},1).')';
   $tctminmaxMeanKernel=' ('.formatTimeInterval($Stats{taskMinTimeKernel},1).'&nbsp;-&nbsp;'.formatTimeInterval($Stats{taskMaxTimeKernel},1).')';
   $tctminmaxMeanKernel2=' ('.formatTimeInterval($AllStats{taskMinTimeKernel},1).'&nbsp;-&nbsp;'.formatTimeInterval($AllStats{taskMaxTimeKernel},1).')';
  } else {
   ($tctMean,$tctMean2,$tctMeanM,$tctMeanM2,$tctMeanS)=('n/a')x5;
   ($tctMeanS2,$tctMeanW,$tctMeanW2,$tctMeanKernel,$tctMeanKernel2)=('n/a')x5;
  }
  $tQueue=$tQueueHigh=$tQueueNorm=$tQueueIdle=$tQueueWait=$tQueueSuspend=0;
  foreach $tid (@Tasks) {
   next unless exists $Tasks{$tid};
   $task=$Tasks{$tid};
   if ($task->{state} eq 'RUN') {
    if ($task->{priority} eq 'HIGH') {
     $tQueueHigh++;
    } elsif ($task->{priority} eq 'NORM') {
     $tQueueNorm++;
    } else { # IDLE priority
     $tQueueIdle++;
    }
   } elsif ($task->{state} eq 'SUSPEND') {
    $tQueueSuspend++;
   } else { # READ WRITE DELAY tasks
    $tQueueWait++;
   }
   $tQueue++;
  }
  # cpu usage
  $cpuUsageAvg=$CanStatCPU ? sprintf(" (%.1f%% avg)",$tots{taskTime}==0 ? 0 : 100*($Stats{taskTimeKernel}+$Stats{taskTimeUser})/$tots{taskTime}) : '';
  $cpuUsageAvg2=$CanStatCPU ? sprintf("%.1f%% avg",$tots{taskTime2}==0 ? 0 : 100*($AllStats{taskTimeKernel}+$AllStats{taskTimeUser})/$tots{taskTime2}) : 'n/a';
  $cpuUsageAvgKernel=$CanStatCPU ? sprintf(" (%.1f%% avg)",$tots{taskTime}==0 ? 0 : 100*$Stats{taskTimeKernel}/$tots{taskTime}) : '';
  $cpuUsageAvgKernel2=$CanStatCPU ? sprintf("%.1f%% avg",$tots{taskTime2}==0 ? 0 : 100*$AllStats{taskTimeKernel}/$tots{taskTime2}) : 'n/a';
  $cpuUsageAvgUser=$CanStatCPU ? sprintf(" (%.1f%% avg)",$tots{taskTime}==0 ? 0 : 100*$Stats{taskTimeUser}/$tots{taskTime}) : '';
  $cpuUsageAvgUser2=$CanStatCPU ? sprintf("%.1f%% avg",$tots{taskTime2}==0 ? 0 : 100*$AllStats{taskTimeUser}/$tots{taskTime2}) : 'n/a';
  $cpuUsageAvgM=$CanStatCPU ? sprintf(" (%.1f%% avg)",$tots{taskTime}==0 ? 0 : 100*$Stats{taskTimeM}/$tots{taskTime}) : '';
  $cpuUsageAvgM2=$CanStatCPU ? sprintf("%.1f%% avg",$tots{taskTime2}==0 ? 0 : 100*$AllStats{taskTimeM}/$tots{taskTime2}) : 'n/a';
  $cpuUsageAvgS=$CanStatCPU ? sprintf(" (%.1f%% avg)",$tots{taskTime}==0 ? 0 : 100*$Stats{taskTimeS}/$tots{taskTime}) : '';
  $cpuUsageAvgS2=$CanStatCPU ? sprintf("%.1f%% avg",$tots{taskTime2}==0 ? 0 : 100*$AllStats{taskTimeS}/$tots{taskTime2}) : 'n/a';
  $cpuUsageAvgW=$CanStatCPU ? sprintf(" (%.1f%% avg)",$tots{taskTime}==0 ? 0 : 100*$Stats{taskTimeW}/$tots{taskTime}) : '';
  $cpuUsageAvgW2=$CanStatCPU ? sprintf("%.1f%% avg",$tots{taskTime2}==0 ? 0 : 100*$AllStats{taskTimeW}/$tots{taskTime2}) : 'n/a';
  # totalled stats
  ($tot_html)=();
  $tot_html.=<<EOT;
      <tbody>
        <tr>
          <td colspan="3" class="sectionHeader" onmousedown="toggleTbody('StatItem1')">Totalled Statistics</td>
        </tr>
      </tbody>
      <tbody id="StatItem1" class="$gpc->{StatItem1}">
        <tr>
          <td class="statsTitle" style="width: 34%"><b>Admin Connections Received:</b></td>
          <td class="statsValue" style="width: 33%">$tots{admConn}</td>
          <td class="statsValue" style="width: 33%">$tots{admConn2}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Admin Connections Accepted:</b></td>
          <td class="statsValue">$Stats{admConn}</td>
          <td class="statsValue">$AllStats{admConn}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Admin Connections Rejected:</b></td>
          <td class="statsValue">$Stats{admConnDenied}</td>
          <td class="statsValue">$AllStats{admConnDenied}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>SMTP Connections Received:</b></td>
          <td class="statsValue">$tots{smtpConn}</td>
          <td class="statsValue">$tots{smtpConn2}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;SMTP Connections Accepted:</b></td>
          <td class="statsValue">$tots{smtpConnAccepted}</td>
          <td class="statsValue">$tots{smtpConnAccepted2}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;SMTP Connections Rejected:</b></td>
          <td class="statsValue">$tots{smtpConnRejected}</td>
          <td class="statsValue">$tots{smtpConnRejected2}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Envelope Senders Processed:</b></td>
          <td class="statsValue">$tots{sender}</td>
          <td class="statsValue">$tots{sender2}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Envelope Senders Accepted:</b></td>
          <td class="statsValue">$tots{senderAccepted}</td>
          <td class="statsValue">$tots{senderAccepted2}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Envelope Senders Rejected:</b></td>
          <td class="statsValue">$tots{senderRejected}</td>
          <td class="statsValue">$tots{senderRejected2}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Envelope Recipients Processed:</b></td>
          <td class="statsValue">$tots{rcpt}</td>
          <td class="statsValue">$tots{rcpt2}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Envelope Recipients Accepted:</b></td>
          <td class="statsValue">$tots{rcptAccepted}</td>
          <td class="statsValue">$tots{rcptAccepted2}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Envelope Recipients Rejected:</b></td>
          <td class="statsValue">$tots{rcptRejected}</td>
          <td class="statsValue">$tots{rcptRejected2}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Messages Processed:</b></td>
          <td class="statsValue">$tots{msgProcessed}</td>
          <td class="statsValue">$tots{msgProcessed2}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Messages Passed:</b></td>
          <td class="statsValue">$tots{msgAccepted}</td>
          <td class="statsValue">$tots{msgAccepted2}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Messages Blocked:</b></td>
          <td class="statsValue">$tots{msgRejected}</td>
          <td class="statsValue">$tots{msgRejected2}</td>
        </tr>
EOT
  if ($DetailedStats) {
   $tot_html.=<<EOT;
        <tr>
          <td class="statsTitle"><b>Bytes Received:</b></td>
          <td class="statsValue">$rbytesSMTP ($prbytesSMTP&nbsp;/&nbsp;$drbytesSMTP)</td>
          <td class="statsValue">$rbytesSMTP2 ($prbytesSMTP2&nbsp;/&nbsp;$drbytesSMTP2)</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Client Side:</b></td>
          <td class="statsValue">$rbytesClientSMTP ($prbytesClientSMTP&nbsp;/&nbsp;$drbytesClientSMTP)</td>
          <td class="statsValue">$rbytesClientSMTP2 ($prbytesClientSMTP2&nbsp;/&nbsp;$drbytesClientSMTP2)</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Server Side:</b></td>
          <td class="statsValue">$rbytesServerSMTP ($prbytesServerSMTP&nbsp;/&nbsp;$drbytesServerSMTP)</td>
          <td class="statsValue">$rbytesServerSMTP2 ($prbytesServerSMTP2&nbsp;/&nbsp;$drbytesServerSMTP2)</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Relay Side:</b></td>
          <td class="statsValue">$rbytesRelaySMTP ($prbytesRelaySMTP&nbsp;/&nbsp;$drbytesRelaySMTP)</td>
          <td class="statsValue">$rbytesRelaySMTP2 ($prbytesRelaySMTP2&nbsp;/&nbsp;$drbytesRelaySMTP2)</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Bytes Transmitted:</b></td>
          <td class="statsValue">$wbytesSMTP ($pwbytesSMTP&nbsp;/&nbsp;$dwbytesSMTP)</td>
          <td class="statsValue">$wbytesSMTP2 ($pwbytesSMTP2&nbsp;/&nbsp;$dwbytesSMTP2)</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Client Side:</b></td>
          <td class="statsValue">$wbytesClientSMTP ($pwbytesClientSMTP&nbsp;/&nbsp;$dwbytesClientSMTP)</td>
          <td class="statsValue">$wbytesClientSMTP2 ($pwbytesClientSMTP2&nbsp;/&nbsp;$dwbytesClientSMTP2)</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Server Side:</b></td>
          <td class="statsValue">$wbytesServerSMTP ($pwbytesServerSMTP&nbsp;/&nbsp;$dwbytesServerSMTP)</td>
          <td class="statsValue">$wbytesServerSMTP2 ($pwbytesServerSMTP2&nbsp;/&nbsp;$dwbytesServerSMTP2)</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Relay Side:</b></td>
          <td class="statsValue">$wbytesRelaySMTP ($pwbytesRelaySMTP&nbsp;/&nbsp;$dwbytesRelaySMTP)</td>
          <td class="statsValue">$wbytesRelaySMTP2 ($pwbytesRelaySMTP2&nbsp;/&nbsp;$dwbytesRelaySMTP2)</td>
        </tr>
EOT
   if ($AvailHiRes) {
    $tot_html.=<<EOT;
        <tr>
          <td class="statsTitle"><b>Receive Throughput:</b></td>
          <td class="statsValue">${\(formatDataSize($rtputSMTP,1).'ps')} (${\(formatDataSize($Stats{rtputMaxSMTP},1).'ps')} max)</td>
          <td class="statsValue">${\(formatDataSize($AllStats{rtputMaxSMTP},1).'ps')} max</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;SMTP Protocol:</b></td>
          <td class="statsValue">${\(formatDataSize($prtputSMTP,1).'ps')} (${\(formatDataSize($Stats{prtputMaxSMTP},1).'ps')} max)</td>
          <td class="statsValue">${\(formatDataSize($AllStats{prtputMaxSMTP},1).'ps')} max</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Client Side:</b></td>
          <td class="statsValue">${\(formatDataSize($prtputClientSMTP,1).'ps')} (${\(formatDataSize($Stats{prtputMaxClientSMTP},1).'ps')} max)</td>
          <td class="statsValue">${\(formatDataSize($AllStats{prtputMaxClientSMTP},1).'ps')} max</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Server Side:</b></td>
          <td class="statsValue">${\(formatDataSize($prtputServerSMTP,1).'ps')} (${\(formatDataSize($Stats{prtputMaxServerSMTP},1).'ps')} max)</td>
          <td class="statsValue">${\(formatDataSize($AllStats{prtputMaxServerSMTP},1).'ps')} max</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Relay Side:</b></td>
          <td class="statsValue">${\(formatDataSize($prtputRelaySMTP,1).'ps')} (${\(formatDataSize($Stats{prtputMaxRelaySMTP},1).'ps')} max)</td>
          <td class="statsValue">${\(formatDataSize($AllStats{prtputMaxRelaySMTP},1).'ps')} max</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;SMTP Data:</b></td>
          <td class="statsValue">${\(formatDataSize($drtputSMTP,1).'ps')} (${\(formatDataSize($Stats{drtputMaxSMTP},1).'ps')} max)</td>
          <td class="statsValue">${\(formatDataSize($AllStats{drtputMaxSMTP},1).'ps')} max</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Client Side:</b></td>
          <td class="statsValue">${\(formatDataSize($drtputClientSMTP,1).'ps')} (${\(formatDataSize($Stats{drtputMaxClientSMTP},1).'ps')} max)</td>
          <td class="statsValue">${\(formatDataSize($AllStats{drtputMaxClientSMTP},1).'ps')} max</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Server Side:</b></td>
          <td class="statsValue">${\(formatDataSize($drtputServerSMTP,1).'ps')} (${\(formatDataSize($Stats{drtputMaxServerSMTP},1).'ps')} max)</td>
          <td class="statsValue">${\(formatDataSize($AllStats{drtputMaxServerSMTP},1).'ps')} max</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Relay Side:</b></td>
          <td class="statsValue">${\(formatDataSize($drtputRelaySMTP,1).'ps')} (${\(formatDataSize($Stats{drtputMaxRelaySMTP},1).'ps')} max)</td>
          <td class="statsValue">${\(formatDataSize($AllStats{drtputMaxRelaySMTP},1).'ps')} max</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Transmit Throughput:</b></td>
          <td class="statsValue">${\(formatDataSize($wtputSMTP,1).'ps')} (${\(formatDataSize($Stats{wtputMaxSMTP},1).'ps')} max)</td>
          <td class="statsValue">${\(formatDataSize($AllStats{wtputMaxSMTP},1).'ps')} max</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;SMTP Protocol:</b></td>
          <td class="statsValue">${\(formatDataSize($pwtputSMTP,1).'ps')} (${\(formatDataSize($Stats{pwtputMaxSMTP},1).'ps')} max)</td>
          <td class="statsValue">${\(formatDataSize($AllStats{pwtputMaxSMTP},1).'ps')} max</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Client Side:</b></td>
          <td class="statsValue">${\(formatDataSize($pwtputClientSMTP,1).'ps')} (${\(formatDataSize($Stats{pwtputMaxClientSMTP},1).'ps')} max)</td>
          <td class="statsValue">${\(formatDataSize($AllStats{pwtputMaxClientSMTP},1).'ps')} max</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Server Side:</b></td>
          <td class="statsValue">${\(formatDataSize($pwtputServerSMTP,1).'ps')} (${\(formatDataSize($Stats{pwtputMaxServerSMTP},1).'ps')} max)</td>
          <td class="statsValue">${\(formatDataSize($AllStats{pwtputMaxServerSMTP},1).'ps')} max</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Relay Side:</b></td>
          <td class="statsValue">${\(formatDataSize($pwtputRelaySMTP,1).'ps')} (${\(formatDataSize($Stats{pwtputMaxRelaySMTP},1).'ps')} max)</td>
          <td class="statsValue">${\(formatDataSize($AllStats{pwtputMaxRelaySMTP},1).'ps')} max</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;SMTP Data:</b></td>
          <td class="statsValue">${\(formatDataSize($dwtputSMTP,1).'ps')} (${\(formatDataSize($Stats{dwtputMaxSMTP},1).'ps')} max)</td>
          <td class="statsValue">${\(formatDataSize($AllStats{dwtputMaxSMTP},1).'ps')} max</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Client Side:</b></td>
          <td class="statsValue">${\(formatDataSize($dwtputClientSMTP,1).'ps')} (${\(formatDataSize($Stats{dwtputMaxClientSMTP},1).'ps')} max)</td>
          <td class="statsValue">${\(formatDataSize($AllStats{dwtputMaxClientSMTP},1).'ps')} max</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Server Side:</b></td>
          <td class="statsValue">${\(formatDataSize($dwtputServerSMTP,1).'ps')} (${\(formatDataSize($Stats{dwtputMaxServerSMTP},1).'ps')} max)</td>
          <td class="statsValue">${\(formatDataSize($AllStats{dwtputMaxServerSMTP},1).'ps')} max</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Relay Side:</b></td>
          <td class="statsValue">${\(formatDataSize($dwtputRelaySMTP,1).'ps')} (${\(formatDataSize($Stats{dwtputMaxRelaySMTP},1).'ps')} max)</td>
          <td class="statsValue">${\(formatDataSize($AllStats{dwtputMaxRelaySMTP},1).'ps')} max</td>
        </tr>
EOT
   } else {
    $tot_html.=<<EOT;
        <tr>
          <td class="statsTitle"><b>Receive Throughput:</b></td>
          <td class="statsValue">n/a</td>
          <td class="statsValue">n/a</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;SMTP Protocol:</b></td>
          <td class="statsValue">n/a</td>
          <td class="statsValue">n/a</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Client Side:</b></td>
          <td class="statsValue">n/a</td>
          <td class="statsValue">n/a</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Server Side:</b></td>
          <td class="statsValue">n/a</td>
          <td class="statsValue">n/a</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Relay Side:</b></td>
          <td class="statsValue">n/a</td>
          <td class="statsValue">n/a</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;SMTP Data:</b></td>
          <td class="statsValue">n/a</td>
          <td class="statsValue">n/a</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Client Side:</b></td>
          <td class="statsValue">n/a</td>
          <td class="statsValue">n/a</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Server Side:</b></td>
          <td class="statsValue">n/a</td>
          <td class="statsValue">n/a</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Relay Side:</b></td>
          <td class="statsValue">n/a</td>
          <td class="statsValue">n/a</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Transmit Throughput:</b></td>
          <td class="statsValue">n/a</td>
          <td class="statsValue">n/a</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;SMTP Protocol:</b></td>
          <td class="statsValue">n/a</td>
          <td class="statsValue">n/a</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Client Side:</b></td>
          <td class="statsValue">n/a</td>
          <td class="statsValue">n/a</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Server Side:</b></td>
          <td class="statsValue">n/a</td>
          <td class="statsValue">n/a</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Relay Side:</b></td>
          <td class="statsValue">n/a</td>
          <td class="statsValue">n/a</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;SMTP Data:</b></td>
          <td class="statsValue">n/a</td>
          <td class="statsValue">n/a</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Client Side:</b></td>
          <td class="statsValue">n/a</td>
          <td class="statsValue">n/a</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Server Side:</b></td>
          <td class="statsValue">n/a</td>
          <td class="statsValue">n/a</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Relay Side:</b></td>
          <td class="statsValue">n/a</td>
          <td class="statsValue">n/a</td>
        </tr>
EOT
   }
  } else {
   $tot_html.=<<EOT;
        <tr>
          <td class="statsTitle"><b>Bytes Received:</b></td>
          <td class="statsValue">$rbytesSMTP</td>
          <td class="statsValue">$rbytesSMTP2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Client Side:</b></td>
          <td class="statsValue">$rbytesClientSMTP</td>
          <td class="statsValue">$rbytesClientSMTP2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Server Side:</b></td>
          <td class="statsValue">$rbytesServerSMTP</td>
          <td class="statsValue">$rbytesServerSMTP2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Relay Side:</b></td>
          <td class="statsValue">$rbytesRelaySMTP</td>
          <td class="statsValue">$rbytesRelaySMTP2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Bytes Transmitted:</b></td>
          <td class="statsValue">$wbytesSMTP</td>
          <td class="statsValue">$wbytesSMTP2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Client Side:</b></td>
          <td class="statsValue">$wbytesClientSMTP</td>
          <td class="statsValue">$wbytesClientSMTP2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Server Side:</b></td>
          <td class="statsValue">$wbytesServerSMTP</td>
          <td class="statsValue">$wbytesServerSMTP2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Relay Side:</b></td>
          <td class="statsValue">$wbytesRelaySMTP</td>
          <td class="statsValue">$wbytesRelaySMTP2</td>
        </tr>
EOT
  }
  $tot_html.=<<EOT;
      </tbody>
EOT
  # averaged stats
  ($mean_html)=();
  $mean_html.=<<EOT;
      <tbody>
        <tr>
          <td colspan="3" class="sectionHeader" onmousedown="toggleTbody('StatItem2')">Averaged Statistics</td>
        </tr>
      </tbody>
      <tbody id="StatItem2" class="$gpc->{StatItem2}">
EOT
  if ($DetailedStats) {
   $mean_html.=<<EOT;
        <tr>
          <td class="statsTitle" style="width: 34%"><b>Mean Message Size:</b></td>
          <td class="statsValue" style="width: 33%">$rbytesMeanMsg ($prbytesMeanMsg&nbsp;/&nbsp;$drbytesMeanMsg)</td>
          <td class="statsValue" style="width: 33%">$rbytesMeanMsg2 ($prbytesMeanMsg2&nbsp;/&nbsp;$drbytesMeanMsg2)</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Passed Ham:</b></td>
          <td class="statsValue">$rbytesMeanHam ($prbytesMeanHam&nbsp;/&nbsp;$drbytesMeanHam)</td>
          <td class="statsValue">$rbytesMeanHam2 ($prbytesMeanHam2&nbsp;/&nbsp;$drbytesMeanHam2)</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Passed Spam:</b></td>
          <td class="statsValue">$rbytesMeanPassedSpam ($prbytesMeanPassedSpam&nbsp;/&nbsp;$drbytesMeanPassedSpam)</td>
          <td class="statsValue">$rbytesMeanPassedSpam2 ($prbytesMeanPassedSpam2&nbsp;/&nbsp;$drbytesMeanPassedSpam2)</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Blocked Spam:</b></td>
          <td class="statsValue">$rbytesMeanBlockedSpam ($prbytesMeanBlockedSpam&nbsp;/&nbsp;$drbytesMeanBlockedSpam)</td>
          <td class="statsValue">$rbytesMeanBlockedSpam2 ($prbytesMeanBlockedSpam2&nbsp;/&nbsp;$drbytesMeanBlockedSpam2)</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Mean Receive Throughput:</b></td>
          <td class="statsValue">$rtputMeanMsg$pdrtputMeanMsg</td>
          <td class="statsValue">$rtputMeanMsg2$pdrtputMeanMsg2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Passed Ham:</b></td>
          <td class="statsValue">$rtputMeanHam$pdrtputMeanHam</td>
          <td class="statsValue">$rtputMeanHam2$pdrtputMeanHam2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Passed Spam:</b></td>
          <td class="statsValue">$rtputMeanPassedSpam$pdrtputMeanPassedSpam</td>
          <td class="statsValue">$rtputMeanPassedSpam2$pdrtputMeanPassedSpam2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Blocked Spam:</b></td>
          <td class="statsValue">$rtputMeanBlockedSpam$pdrtputMeanBlockedSpam</td>
          <td class="statsValue">$rtputMeanBlockedSpam2$pdrtputMeanBlockedSpam2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Mean Client Latency:</b></td>
          <td class="statsValue">$lBanner$lMean$lminmaxMean$lMeanSuffix</td>
          <td class="statsValue">$lBanner2$lMean2$lminmaxMean2$lMeanSuffix</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Passed Ham:</b></td>
          <td class="statsValue">$lBannerHam$lMeanHam$lminmaxMeanHam$lMeanSuffix</td>
          <td class="statsValue">$lBannerHam2$lMeanHam2$lminmaxMeanHam2$lMeanSuffix</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Passed Spam:</b></td>
          <td class="statsValue">$lBannerPassedSpam$lMeanPassedSpam$lminmaxMeanPassedSpam$lMeanSuffix</td>
          <td class="statsValue">$lBannerPassedSpam2$lMeanPassedSpam2$lminmaxMeanPassedSpam2$lMeanSuffix</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Blocked Spam:</b></td>
          <td class="statsValue">$lBannerBlockedSpam$lMeanBlockedSpam$lminmaxMeanBlockedSpam$lMeanSuffix</td>
          <td class="statsValue">$lBannerBlockedSpam2$lMeanBlockedSpam2$lminmaxMeanBlockedSpam2$lMeanSuffix</td>
        </tr>
EOT
  } else {
   $mean_html.=<<EOT;
        <tr>
          <td class="statsTitle" style="width: 34%"><b>Mean Message Size:</b></td>
          <td class="statsValue" style="width: 33%">$rbytesMeanMsg</td>
          <td class="statsValue" style="width: 33%">$rbytesMeanMsg2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Passed Ham:</b></td>
          <td class="statsValue">$rbytesMeanHam</td>
          <td class="statsValue">$rbytesMeanHam2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Passed Spam:</b></td>
          <td class="statsValue">$rbytesMeanPassedSpam</td>
          <td class="statsValue">$rbytesMeanPassedSpam2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Blocked Spam:</b></td>
          <td class="statsValue">$rbytesMeanBlockedSpam</td>
          <td class="statsValue">$rbytesMeanBlockedSpam2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Mean Receive Throughput:</b></td>
          <td class="statsValue">$rtputMeanMsg</td>
          <td class="statsValue">$rtputMeanMsg2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Passed Ham:</b></td>
          <td class="statsValue">$rtputMeanHam</td>
          <td class="statsValue">$rtputMeanHam2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Passed Spam:</b></td>
          <td class="statsValue">$rtputMeanPassedSpam</td>
          <td class="statsValue">$rtputMeanPassedSpam2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Blocked Spam:</b></td>
          <td class="statsValue">$rtputMeanBlockedSpam</td>
          <td class="statsValue">$rtputMeanBlockedSpam2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Mean Client Latency:</b></td>
          <td class="statsValue">$lBanner$lMean$lMeanSuffix</td>
          <td class="statsValue">$lBanner2$lMean2$lMeanSuffix</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Passed Ham:</b></td>
          <td class="statsValue">$lBannerHam$lMeanHam$lMeanSuffix</td>
          <td class="statsValue">$lBannerHam2$lMeanHam2$lMeanSuffix</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Passed Spam:</b></td>
          <td class="statsValue">$lBannerPassedSpam$lMeanPassedSpam$lMeanSuffix</td>
          <td class="statsValue">$lBannerPassedSpam2$lMeanPassedSpam2$lMeanSuffix</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Blocked Spam:</b></td>
          <td class="statsValue">$lBannerBlockedSpam$lMeanBlockedSpam$lMeanSuffix</td>
          <td class="statsValue">$lBannerBlockedSpam2$lMeanBlockedSpam2$lMeanSuffix</td>
        </tr>
EOT
  }
  $mean_html.=<<EOT;
      </tbody>
EOT
  # messages
  ($msg_html)=();
  $msg_html.=<<EOT;
      <tbody>
        <tr>
          <td colspan="3" class="sectionHeader" onmousedown="toggleTbody('StatItem7')">Messages Statistics</td>
        </tr>
      </tbody>
      <tbody id="StatItem7" class="$gpc->{StatItem7}">
EOT
  foreach $i (@StatsMsgItems) {
   $name=('&nbsp;'x(4*$i->[0])).$i->[1];
   $class=$i->[2];
   $value1=$Stats{$i->[3]};
   $value2=$AllStats{$i->[3]};
   $msg_html.=<<EOT;
        <tr>
          <td class="statsTitle" style="width: 34%"><b>$name</b></td>
          <td class="statsValue $class" style="width: 33%">$value1</td>
          <td class="statsValue $class" style="width: 33%">$value2</td>
        </tr>
EOT
  }
  $msg_html.=<<EOT;
      </tbody>
EOT
  # traffic
  ($traf_html)=();
  $traf_html.=<<EOT;
      <tbody>
        <tr>
          <td colspan="3" class="sectionHeader" onmousedown="toggleTbody('StatItem8')">Traffic Statistics</td>
        </tr>
      </tbody>
      <tbody id="StatItem8" class="$gpc->{StatItem8}">
EOT
  foreach $i (@StatsTrafItems) {
   $name=('&nbsp;'x(4*$i->[0])).$i->[1];
   $class=$i->[2];
   $value1=formatDataSize($Stats{'p'.$i->[3]}+$Stats{'d'.$i->[3]},1);
   if ($DetailedStats) {
    $value1.=' ('.formatDataSize($Stats{'p'.$i->[3]},1).'&nbsp;/&nbsp;'.
                  formatDataSize($Stats{'d'.$i->[3]},1).')';
   }
   $value2=formatDataSize($AllStats{'p'.$i->[3]}+$AllStats{'d'.$i->[3]},1);
   if ($DetailedStats) {
    $value2.=' ('.formatDataSize($AllStats{'p'.$i->[3]},1).'&nbsp;/&nbsp;'.
                  formatDataSize($AllStats{'d'.$i->[3]},1).')';
   }
   $traf_html.=<<EOT;
        <tr>
          <td class="statsTitle" style="width: 34%"><b>$name</b></td>
          <td class="statsValue $class" style="width: 33%">$value1</td>
          <td class="statsValue $class" style="width: 33%">$value2</td>
        </tr>
EOT
  }
  $traf_html.=<<EOT;
      </tbody>
EOT
  # providers
  ($prov_html)=();
  $prov_html.=<<EOT;
      <tbody>
        <tr>
          <td colspan="3" class="sectionHeader" onmousedown="toggleTbody('StatItem9')">Providers Statistics</td>
        </tr>
      </tbody>
      <tbody id="StatItem9" class="$gpc->{StatItem9}">
EOT
  foreach $i ('RWL',@rwllist,'SPF','RBL',@rbllist,'URIBL',@uribllist) {
   if ($i=~/\./) {
    # provider
    $name=('&nbsp;'x4).$i;
    $value1=$Stats{"providerReplies$i"}.'/'.$Stats{"providerHits$i"};
    if ($AvailHiRes) {
     $value1.=' '.formatTimeInterval($Stats{"providerReplies$i"} ? $Stats{"providerTime$i"}/$Stats{"providerReplies$i"} : 0,1).' avg';
    } else {
     $value1.=' n/a';
    }
    $value2=$AllStats{"providerReplies$i"}.'/'.$AllStats{"providerHits$i"};
    if ($AvailHiRes) {
     $value2.=' '.formatTimeInterval($AllStats{"providerReplies$i"} ? $AllStats{"providerTime$i"}/$AllStats{"providerReplies$i"} : 0,1).' avg';
    } else {
     $value2.=' n/a';
    }
   } else {
    # service
    $name="$i Service Providers:";
    $value1=$Stats{"providerQueries$i"};
    if ($AvailHiRes) {
     $value1.=' / '.formatTimeInterval($Stats{"providerQueries$i"} ? $Stats{"providerTime$i"}/$Stats{"providerQueries$i"} : 0,1).' avg';
    } else {
     $value1.=' n/a';
    }
    $value2=$AllStats{"providerQueries$i"};
    if ($AvailHiRes) {
     $value2.=' / '.formatTimeInterval($AllStats{"providerQueries$i"} ? $AllStats{"providerTime$i"}/$AllStats{"providerQueries$i"} : 0,1).' avg';
    } else {
     $value2.=' n/a';
    }
   }
   if ($DetailedStats && $AvailHiRes) {
    $value1.=' ('.formatTimeInterval($Stats{"providerMinTime$i"},1).'&nbsp;-&nbsp;'.
                  formatTimeInterval($Stats{"providerMaxTime$i"},1).')';
    $value2.=' ('.formatTimeInterval($AllStats{"providerMinTime$i"},1).'&nbsp;-&nbsp;'.
                  formatTimeInterval($AllStats{"providerMaxTime$i"},1).')';
   }
   $prov_html.=<<EOT;
        <tr>
          <td class="statsTitle" style="width: 34%"><b>$name</b></td>
          <td class="statsValue" style="width: 33%">$value1</td>
          <td class="statsValue" style="width: 33%">$value2</td>
        </tr>
EOT
  }
  $prov_html.=<<EOT;
      </tbody>
EOT
  # throughput
  ($tput_html)=();
  if ($DetailedStats) {
   $tput_html.=<<EOT;
      <tbody>
        <tr>
          <td colspan="3" class="sectionHeader" onmousedown="toggleTbody('StatItem10')">Throughput Statistics</td>
        </tr>
      </tbody>
      <tbody id="StatItem10" class="$gpc->{StatItem10}">
EOT
   foreach $i (@StatsMsgItems) {
    $name=('&nbsp;'x(4*$i->[0])).$i->[1];
    $class=$i->[2];
    if ($AvailHiRes) {
     $value1=formatDataSize(($Stats{'prtime'.$i->[3]}+$Stats{'drtime'.$i->[3]})==0 ? 0 : ($Stats{'prbytes'.$i->[3]}+$Stats{'drbytes'.$i->[3]})/($Stats{'prtime'.$i->[3]}+$Stats{'drtime'.$i->[3]}),1).'ps ('.
             formatDataSize($Stats{'prtime'.$i->[3]}==0 ? 0 : $Stats{'prbytes'.$i->[3]}/$Stats{'prtime'.$i->[3]},1).'ps&nbsp;/&nbsp;'.
             formatDataSize($Stats{'drtime'.$i->[3]}==0 ? 0 : $Stats{'drbytes'.$i->[3]}/$Stats{'drtime'.$i->[3]},1).'ps)';
     $value2=formatDataSize(($AllStats{'prtime'.$i->[3]}+$AllStats{'drtime'.$i->[3]})==0 ? 0 : ($AllStats{'prbytes'.$i->[3]}+$AllStats{'drbytes'.$i->[3]})/($AllStats{'prtime'.$i->[3]}+$AllStats{'drtime'.$i->[3]}),1).'ps ('.
             formatDataSize($AllStats{'prtime'.$i->[3]}==0 ? 0 : $AllStats{'prbytes'.$i->[3]}/$AllStats{'prtime'.$i->[3]},1).'ps&nbsp;/&nbsp;'.
             formatDataSize($AllStats{'drtime'.$i->[3]}==0 ? 0 : $AllStats{'drbytes'.$i->[3]}/$AllStats{'drtime'.$i->[3]},1).'ps)';
    } else {
     $value1='n/a';
     $value2='n/a';
    }
    $tput_html.=<<EOT;
        <tr>
          <td class="statsTitle" style="width: 34%"><b>$name</b></td>
          <td class="statsValue $class" style="width: 33%">$value1</td>
          <td class="statsValue $class" style="width: 33%">$value2</td>
        </tr>
EOT
   }
   $tput_html.=<<EOT;
      </tbody>
EOT
  }
  # latency
  ($lncy_html)=();
  if ($DetailedStats) {
   $lncy_html.=<<EOT;
      <tbody>
        <tr>
          <td colspan="3" class="sectionHeader" onmousedown="toggleTbody('StatItem11')">Latency Statistics</td>
        </tr>
      </tbody>
      <tbody id="StatItem11" class="$gpc->{StatItem11}">
EOT
   foreach $i (@StatsMsgItems) {
    $name=('&nbsp;'x(4*$i->[0])).$i->[1];
    $class=$i->[2];
    if ($AvailHiRes) {
     $value1=formatTimeInterval($Stats{$i->[3]}==0 ? 0 : $Stats{'lbanner'.$i->[3]}/$Stats{$i->[3]},1).' ttfb / '.
             formatTimeInterval($Stats{$i->[3]}==0 ? 0 : ($Stats{'lmin'.$i->[3]}+$Stats{'lmax'.$i->[3]})/(2*$Stats{$i->[3]}),1).' '.
         '('.formatTimeInterval($Stats{$i->[3]}==0 ? 0 : $Stats{'lmin'.$i->[3]}/$Stats{$i->[3]},1).'&nbsp;-&nbsp;'.
             formatTimeInterval($Stats{$i->[3]}==0 ? 0 : $Stats{'lmax'.$i->[3]}/$Stats{$i->[3]},1).') avg';
     $value2=formatTimeInterval($AllStats{$i->[3]}==0 ? 0 : $AllStats{'lbanner'.$i->[3]}/$AllStats{$i->[3]},1).' ttfb / '.
             formatTimeInterval($AllStats{$i->[3]}==0 ? 0 : ($AllStats{'lmin'.$i->[3]}+$AllStats{'lmax'.$i->[3]})/(2*$AllStats{$i->[3]}),1).' '.
         '('.formatTimeInterval($AllStats{$i->[3]}==0 ? 0 : $AllStats{'lmin'.$i->[3]}/$AllStats{$i->[3]},1).'&nbsp;-&nbsp;'.
             formatTimeInterval($AllStats{$i->[3]}==0 ? 0 : $AllStats{'lmax'.$i->[3]}/$AllStats{$i->[3]},1).') avg';
    } else {
     $value1='n/a';
     $value2='n/a';
    }
    $lncy_html.=<<EOT;
        <tr>
          <td class="statsTitle" style="width: 34%"><b>$name</b></td>
          <td class="statsValue $class" style="width: 33%">$value1</td>
          <td class="statsValue $class" style="width: 33%">$value2</td>
        </tr>
EOT
   }
   $lncy_html.=<<EOT;
      </tbody>
EOT
  }
  ($task_html)=();
  if ($DetailedStats) {
   $task_html.=<<EOT;
      <tbody>
        <tr>
          <td colspan="3" class="sectionHeader" onmousedown="toggleTbody('StatItem12')">Tasks Statistics</td>
        </tr>
      </tbody>
      <tbody id="StatItem12" class="$gpc->{StatItem12}">
        <tr>
          <td class="statsTitle" style="width: 34%"><b>Tasks Created/Finished:</b></td>
          <td class="statsValue" style="width: 33%">$tots{taskCreated}/$tots{taskFinished}</td>
          <td class="statsValue" style="width: 33%">$tots{taskCreated2}/$tots{taskFinished2}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Main:</b></td>
          <td class="statsValue">$Stats{taskCreatedM}/$Stats{taskFinishedM}</td>
          <td class="statsValue">$AllStats{taskCreatedM}/$AllStats{taskFinishedM}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;SMTP:</b></td>
          <td class="statsValue">$Stats{taskCreatedS}/$Stats{taskFinishedS}</td>
          <td class="statsValue">$AllStats{taskCreatedS}/$AllStats{taskFinishedS}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Web:</b></td>
          <td class="statsValue">$Stats{taskCreatedW}/$Stats{taskFinishedW}</td>
          <td class="statsValue">$AllStats{taskCreatedW}/$AllStats{taskFinishedW}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Tasks Active:</b></td>
          <td class="statsValue">$tActive ($Stats{taskMaxActive} max)</td>
          <td class="statsValue">$AllStats{taskMaxActive} max</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Main:</b></td>
          <td class="statsValue">$tActiveM ($Stats{taskMaxActiveM} max)</td>
          <td class="statsValue">$AllStats{taskMaxActiveM} max</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;SMTP:</b></td>
          <td class="statsValue">$tActiveS ($Stats{taskMaxActiveS} max)</td>
          <td class="statsValue">$AllStats{taskMaxActiveS} max</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Web:</b></td>
          <td class="statsValue">$tActiveW ($Stats{taskMaxActiveW} max)</td>
          <td class="statsValue">$AllStats{taskMaxActiveW} max</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>User Calls:</b></td>
          <td class="statsValue">$tots{taskCalls} / $tctMean$tctminmaxMean</td>
          <td class="statsValue">$tots{taskCalls2} / $tctMean2$tctminmaxMean2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Main:</b></td>
          <td class="statsValue">$Stats{taskCallsM} / $tctMeanM$tctminmaxMeanM</td>
          <td class="statsValue">$AllStats{taskCallsM} / $tctMeanM2$tctminmaxMeanM2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;SMTP:</b></td>
          <td class="statsValue">$Stats{taskCallsS} / $tctMeanS$tctminmaxMeanS</td>
          <td class="statsValue">$AllStats{taskCallsS} / $tctMeanS2$tctminmaxMeanS2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Web:</b></td>
          <td class="statsValue">$Stats{taskCallsW} / $tctMeanW$tctminmaxMeanW</td>
          <td class="statsValue">$AllStats{taskCallsW} / $tctMeanW2$tctminmaxMeanW2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Kernel Calls:</b></td>
          <td class="statsValue">$Stats{taskCallsKernel} / $tctMeanKernel$tctminmaxMeanKernel</td>
          <td class="statsValue">$AllStats{taskCallsKernel} / $tctMeanKernel2$tctminmaxMeanKernel2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Call Queue Length:</b></td>
          <td class="statsValue">$tQueue ($Stats{taskMaxQueue} max)</td>
          <td class="statsValue">$AllStats{taskMaxQueue} max</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;High Priority:</b></td>
          <td class="statsValue">$tQueueHigh ($Stats{taskMaxQueueHigh} max)</td>
          <td class="statsValue">$AllStats{taskMaxQueueHigh} max</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Normal Priority:</b></td>
          <td class="statsValue">$tQueueNorm ($Stats{taskMaxQueueNorm} max)</td>
          <td class="statsValue">$AllStats{taskMaxQueueNorm} max</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Idle Priority:</b></td>
          <td class="statsValue">$tQueueIdle ($Stats{taskMaxQueueIdle} max)</td>
          <td class="statsValue">$AllStats{taskMaxQueueIdle} max</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Waiting Calls:</b></td>
          <td class="statsValue">$tQueueWait ($Stats{taskMaxQueueWait} max)</td>
          <td class="statsValue">$AllStats{taskMaxQueueWait} max</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Suspended Calls:</b></td>
          <td class="statsValue">$tQueueSuspend ($Stats{taskMaxQueueSuspend} max)</td>
          <td class="statsValue">$AllStats{taskMaxQueueSuspend} max</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>User CPU Usage:</b></td>
          <td class="statsValue">$cpuUsageUser$cpuUsageAvgUser</td>
          <td class="statsValue">$cpuUsageAvgUser2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Main:</b></td>
          <td class="statsValue">$cpuUsageM$cpuUsageAvgM</td>
          <td class="statsValue">$cpuUsageAvgM2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;SMTP:</b></td>
          <td class="statsValue">$cpuUsageS$cpuUsageAvgS</td>
          <td class="statsValue">$cpuUsageAvgS2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Web:</b></td>
          <td class="statsValue">$cpuUsageW$cpuUsageAvgW</td>
          <td class="statsValue">$cpuUsageAvgW2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Kernel CPU Usage:</b></td>
          <td class="statsValue">$cpuUsageKernel$cpuUsageAvgKernel</td>
          <td class="statsValue">$cpuUsageAvgKernel2</td>
        </tr>
      </tbody>
EOT
  }
  return <<EOT;
$HTTPHeaderOK
$HTMLHeaderDTDStrict
$HTMLHeaders
  <script type="text/javascript" src="get?file=images/cookies.js"></script>
  <script type="text/javascript">
  <!--
    function toggleTbody(id) {
      if (document.getElementById) {
        var tbod=document.getElementById(id);
        if (tbod && typeof tbod.className=='string') {
          if (tbod.className=='off') {
            tbod.className='on';
          } else {
            tbod.className='off';
          }
          var cookie_exp=new Date();
          cookie_exp.setTime(cookie_exp.getTime()+2592000*1000); //1 month (milliseconds)
          setCookie('last_'+id,tbod.className,cookie_exp);
        }
      }
      return false;
    }
  //-->
  </script>
  <div class="content">
    <h2>ASSP Statistics</h2>
    <br />
    <table class="statBox" style="width: 98%">
      <thead>
        <tr>
          <td colspan="3" class="sectionHeader" onmousedown="toggleTbody('StatItem0')">General Runtime Information</td>
        </tr>
      </thead>
      <tbody id="StatItem0" class="$gpc->{StatItem0}">
        <tr>
          <td class="statsTitle" style="width: 34%"><b>ASSP Proxy Uptime:</b></td>
          <td class="statsValue" style="width: 33%">$uptime</td>
          <td class="statsValue" style="width: 33%">$uptime2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Messages Processed:</b></td>
          <td class="statsValue">$tots{msgProcessed} ($mpd per day)</td>
          <td class="statsValue">$tots{msgProcessed2} ($mpd2 per day)</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Non-Local Mail Blocked:</b></td>
          <td class="statsValue">$pct%</td>
          <td class="statsValue">$pct2%</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>CPU Usage:</b></td>
          <td class="statsValue">$cpuUsage$cpuUsageAvg</td>
          <td class="statsValue">$cpuUsageAvg2</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Concurrent SMTP Sessions:</b></td>
          <td class="statsValue">$sessCnt ($Stats{smtpMaxConcurrentSessions} max)</td>
          <td class="statsValue">$AllStats{smtpMaxConcurrentSessions} max</td>
        </tr>
      </tbody>
$tot_html
$mean_html
      <tbody>
        <tr>
          <td colspan="3" class="sectionHeader" onmousedown="toggleTbody('StatItem3')">SMTP Connections Statistics</td>
        </tr>
      </tbody>
      <tbody id="StatItem3" class="$gpc->{StatItem3}">
        <tr>
          <td class="statsTitle" style="width: 34%"><b>Accepted Logged SMTP Connections:</b></td>
          <td class="statsValue positive" style="width: 33%">$Stats{smtpConn}</td>
          <td class="statsValue positive" style="width: 33%">$AllStats{smtpConn}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Not Logged SMTP Connections:</b></td>
          <td class="statsValue positive">$Stats{smtpConnNotLogged}</td>
          <td class="statsValue positive">$AllStats{smtpConnNotLogged}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>SMTP Connection Limits:</b></td>
          <td class="statsValue negative">$tots{smtpConnLimit}</td>
          <td class="statsValue negative">$tots{smtpConnLimit2}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Overall Limits:</b></td>
          <td class="statsValue negative">$Stats{smtpConnLimit}</td>
          <td class="statsValue negative">$AllStats{smtpConnLimit}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;By IP Limits:</b></td>
          <td class="statsValue negative">$Stats{smtpConnLimitIP}</td>
          <td class="statsValue negative">$AllStats{smtpConnLimitIP}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Denied SMTP Connections:</b></td>
          <td class="statsValue negative">$Stats{smtpConnDenied}</td>
          <td class="statsValue negative">$AllStats{smtpConnDenied}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>RateLimit Blocked SMTP Connections:</b></td>
          <td class="statsValue negative">$Stats{smtpConnRateLimit}</td>
          <td class="statsValue negative">$AllStats{smtpConnRateLimit}</td>
        </tr>
      </tbody>
      <tbody>
        <tr>
          <td colspan="3" class="sectionHeader" onmousedown="toggleTbody('StatItem4')">Clients Statistics</td>
        </tr>
      </tbody>
      <tbody id="StatItem4" class="$gpc->{StatItem4}">
        <tr>
          <td class="statsTitle" style="width: 34%"><b>Client Helos Accepted:</b></td>
          <td class="statsValue positive" style="width: 33%">$tots{clientAcceptedHelo}</td>
          <td class="statsValue positive" style="width: 33%">$tots{clientAcceptedHelo2}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Validated Helos:</b></td>
          <td class="statsValue positive">$Stats{clientHeloValidated}</td>
          <td class="statsValue positive">$AllStats{clientHeloValidated}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Unchecked Helos:</b></td>
          <td class="statsValue positive">$Stats{clientHeloUnchecked}</td>
          <td class="statsValue positive">$AllStats{clientHeloUnchecked}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Client Helos Rejected:</b></td>
          <td class="statsValue negative">$tots{clientRejectedHelo}</td>
          <td class="statsValue negative">$tots{clientRejectedHelo2}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Forged Helos:</b></td>
          <td class="statsValue negative">$Stats{clientHeloForged}</td>
          <td class="statsValue negative">$AllStats{clientHeloForged}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Blacklisted Helos:</b></td>
          <td class="statsValue negative">$Stats{clientHeloBlacklisted}</td>
          <td class="statsValue negative">$AllStats{clientHeloBlacklisted}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Mismatched Helos:</b></td>
          <td class="statsValue negative">$Stats{clientHeloMismatch}</td>
          <td class="statsValue negative">$AllStats{clientHeloMismatch}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Spam Helos:</b></td>
          <td class="statsValue negative">$Stats{clientHeloSpam}</td>
          <td class="statsValue negative">$AllStats{clientHeloSpam}</td>
        </tr>
      </tbody>
      <tbody>
        <tr>
          <td colspan="3" class="sectionHeader" onmousedown="toggleTbody('StatItem5')">Senders Statistics</td>
        </tr>
      </tbody>
      <tbody id="StatItem5" class="$gpc->{StatItem5}">
        <tr>
          <td class="statsTitle" style="width: 34%"><b>Local Senders Accepted:</b></td>
          <td class="statsValue positive" style="width: 33%">$tots{senderAcceptedLocal}</td>
          <td class="statsValue positive" style="width: 33%">$tots{senderAcceptedLocal2}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Validated Senders:</b></td>
          <td class="statsValue positive">$Stats{senderValidatedLocal}</td>
          <td class="statsValue positive">$AllStats{senderValidatedLocal}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Unchecked Senders:</b></td>
          <td class="statsValue positive">$Stats{senderUncheckedLocal}</td>
          <td class="statsValue positive">$AllStats{senderUncheckedLocal}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Remote Senders Accepted:</b></td>
          <td class="statsValue positive">$tots{senderAcceptedRemote}</td>
          <td class="statsValue positive">$tots{senderAcceptedRemote2}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Whitelisted Senders:</b></td>
          <td class="statsValue positive">$Stats{senderWhitelisted}</td>
          <td class="statsValue positive">$AllStats{senderWhitelisted}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Validated Senders:</b></td>
          <td class="statsValue positive">$Stats{senderValidatedRemote}</td>
          <td class="statsValue positive">$AllStats{senderValidatedRemote}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Unchecked Senders:</b></td>
          <td class="statsValue positive">$Stats{senderUncheckedRemote}</td>
          <td class="statsValue positive">$AllStats{senderUncheckedRemote}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Noprocessed Senders:</b></td>
          <td class="statsValue positive">$Stats{senderUnprocessed}</td>
          <td class="statsValue positive">$AllStats{senderUnprocessed}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Local Senders Rejected:</b></td>
          <td class="statsValue negative">$tots{senderRejectedLocal}</td>
          <td class="statsValue negative">$tots{senderRejectedLocal2}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Forged Senders:</b></td>
          <td class="statsValue negative">$Stats{senderForged}</td>
          <td class="statsValue negative">$AllStats{senderForged}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Remote Senders Rejected:</b></td>
          <td class="statsValue negative">$tots{senderRejectedRemote}</td>
          <td class="statsValue negative">$tots{senderRejectedRemote2}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Nonexistent MX Senders:</b></td>
          <td class="statsValue negative">$Stats{senderNoMX}</td>
          <td class="statsValue negative">$AllStats{senderNoMX}</td>
        </tr>
      </tbody>
      <tbody>
        <tr>
          <td colspan="3" class="sectionHeader" onmousedown="toggleTbody('StatItem6')">Recipients Statistics</td>
        </tr>
      </tbody>
      <tbody id="StatItem6" class="$gpc->{StatItem6}">
        <tr>
          <td class="statsTitle" style="width: 34%"><b>Local Recipients Accepted:</b></td>
          <td class="statsValue positive" style="width: 33%">$tots{rcptAcceptedLocal}</td>
          <td class="statsValue positive" style="width: 33%">$tots{rcptAcceptedLocal2}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Validated Recipients:</b></td>
          <td class="statsValue positive">$Stats{rcptValidated}</td>
          <td class="statsValue positive">$AllStats{rcptValidated}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Unchecked Recipients:</b></td>
          <td class="statsValue positive">$Stats{rcptUnchecked}</td>
          <td class="statsValue positive">$AllStats{rcptUnchecked}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Spam-Lover Recipients:</b></td>
          <td class="statsValue positive">$Stats{rcptSpamLover}</td>
          <td class="statsValue positive">$AllStats{rcptSpamLover}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Remote Recipients Accepted:</b></td>
          <td class="statsValue positive">$tots{rcptAcceptedRemote}</td>
          <td class="statsValue positive">$tots{rcptAcceptedRemote2}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Whitelisted Recipients:</b></td>
          <td class="statsValue positive">$Stats{rcptWhitelisted}</td>
          <td class="statsValue positive">$AllStats{rcptWhitelisted}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Not Whitelisted Recipients:</b></td>
          <td class="statsValue positive">$Stats{rcptNotWhitelisted}</td>
          <td class="statsValue positive">$AllStats{rcptNotWhitelisted}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Noprocessed Recipients:</b></td>
          <td class="statsValue positive">$Stats{rcptUnprocessed}</td>
          <td class="statsValue positive">$AllStats{rcptUnprocessed}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Email Reports:</b></td>
          <td class="statsValue positive">$tots{rcptReport}</td>
          <td class="statsValue positive">$tots{rcptReport2}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Spam Reports:</b></td>
          <td class="statsValue positive">$Stats{rcptReportSpam}</td>
          <td class="statsValue positive">$AllStats{rcptReportSpam}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Ham Reports:</b></td>
          <td class="statsValue positive">$Stats{rcptReportHam}</td>
          <td class="statsValue positive">$AllStats{rcptReportHam}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Whitelist Additions:</b></td>
          <td class="statsValue positive">$Stats{rcptReportWhitelistAdd}</td>
          <td class="statsValue positive">$AllStats{rcptReportWhitelistAdd}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Whitelist Deletions:</b></td>
          <td class="statsValue positive">$Stats{rcptReportWhitelistRemove}</td>
          <td class="statsValue positive">$AllStats{rcptReportWhitelistRemove}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Redlist Additions:</b></td>
          <td class="statsValue positive">$Stats{rcptReportRedlistAdd}</td>
          <td class="statsValue positive">$AllStats{rcptReportRedlistAdd}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Redlist Deletions:</b></td>
          <td class="statsValue positive">$Stats{rcptReportRedlistRemove}</td>
          <td class="statsValue positive">$AllStats{rcptReportRedlistRemove}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Local Recipients Rejected:</b></td>
          <td class="statsValue negative">$tots{rcptRejectedLocal}</td>
          <td class="statsValue negative">$tots{rcptRejectedLocal2}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Nonexistent Recipients:</b></td>
          <td class="statsValue negative">$Stats{rcptNonexistent}</td>
          <td class="statsValue negative">$AllStats{rcptNonexistent}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Delayed Recipients:</b></td>
          <td class="statsValue negative">$Stats{rcptDelayed}</td>
          <td class="statsValue negative">$AllStats{rcptDelayed}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Delayed (Late) Recipients:</b></td>
          <td class="statsValue negative">$Stats{rcptDelayedLate}</td>
          <td class="statsValue negative">$AllStats{rcptDelayedLate}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Delayed (Expired) Recipients:</b></td>
          <td class="statsValue negative">$Stats{rcptDelayedExpired}</td>
          <td class="statsValue negative">$AllStats{rcptDelayedExpired}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Embargoed Recipients:</b></td>
          <td class="statsValue negative">$Stats{rcptEmbargoed}</td>
          <td class="statsValue negative">$AllStats{rcptEmbargoed}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Spam Trap Recipients:</b></td>
          <td class="statsValue negative">$Stats{rcptSpamBucket}</td>
          <td class="statsValue negative">$AllStats{rcptSpamBucket}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>Remote Recipients Rejected:</b></td>
          <td class="statsValue negative">$tots{rcptRejectedRemote}</td>
          <td class="statsValue negative">$tots{rcptRejectedRemote2}</td>
        </tr>
        <tr>
          <td class="statsTitle"><b>&nbsp;&nbsp;&nbsp;&nbsp;Relay Attempts:</b></td>
          <td class="statsValue negative">$Stats{rcptRelayRejected}</td>
          <td class="statsValue negative">$AllStats{rcptRelayRejected}</td>
        </tr>
      </tbody>
$msg_html
$traf_html
$prov_html
$tput_html
$lncy_html
$task_html
    </table>
    <form action="" method="post">
      <div class="rightButton">
        <input type="submit" name="action" value="Reset Statistics">
      </div>
    </form>
  </div>
$HTMLFooters
</body>
</html>
EOT
 }];
 &{$sref->[0]};
 return $sref->[1];
}

sub textinput {
 my ($name,$nicename,$size,$func,$default,$valid,$onchange,$description,$data,$http,$gpc)=@_;
 my $Error=checkUpdate($name,$default,$valid,$onchange,$http,$gpc);
 my $value=encodeHTMLEntities($Config{$name});
 my $edit;
 if ($value=~/^ *file: *(.+)/i) {
  # the option list is actually saved in a file.
  $edit='<input type="button" value=" Edit file " onClick="popFileEditor(\''.escapeQuery($1).'\',1);">';
 }
 $name=~s/(e)(mail)/$1_$2/gi; # get rid of google autofill
 my $news=$Config{ShowNews} && $News{$name} ? ' news' : '';
 my $s="$Error$description";
 if ($s) {
  $s=<<EOT;
            <div class="optionValue$news" style="margin-top: 5px;">
              $s
            </div>
EOT
 }
 return <<EOT;
        <a name="$name"></a>
        <div class="shadow">
          <div class="option$news">
            <div class="optionTitle$news">
              $nicename
            </div>
            <div class="optionValue$news">
              <input name="$name" size="$size" value="$value" />$edit
            </div>
$s
          </div>
        </div>
EOT
}

sub RLIBTtextinput {
 my ($name,$nicename,$size,$func,$default,$valid,$onchange,$description,$data,$http,$gpc)=@_;
 if (RLIBTEventEnabled($name)) {
  return textinput($name,$nicename,$size,$func,$default,$valid,$onchange,$description,$data,$http,$gpc);
 } else {
 my $value=encodeHTMLEntities($Config{$name});
 $name=~s/(e)(mail)/$1_$2/gi; # get rid of google autofill
 return <<EOT;
        <input type="hidden" name="$name" value="$value" />
EOT
 }
}

sub Avtextinput {
 my ($name,$nicename,$size,$func,$default,$valid,$onchange,$description,$data,$http,$gpc)=@_;
 if (AvOptionEnabled($name)) {
  return textinput($name,$nicename,$size,$func,$default,$valid,$onchange,$description,$data,$http,$gpc);
 } else {
 my $value=encodeHTMLEntities($Config{$name});
 $name=~s/(e)(mail)/$1_$2/gi; # get rid of google autofill
 return <<EOT;
        <input type="hidden" name="$name" value="$value" />
EOT
 }
}

# everybody wants this, but I hate it -- use it if you care.
sub passwdinput {
 my ($name,$nicename,$size,$func,$default,$valid,$onchange,$description,$data,$http,$gpc)=@_;
 my $Error=checkUpdate($name,$default,$valid,$onchange,$http,$gpc);
 my $value=encodeHTMLEntities($Config{$name});
 my $news=$Config{ShowNews} && $News{$name} ? ' news' : '';
 my $s="$Error$description";
 if ($s) {
  $s=<<EOT;
            <div class="optionValue$news" style="margin-top: 5px;">
              $s
            </div>
EOT
 }
 return <<EOT;
        <a name="$name"></a>
        <div class="shadow">
          <div class="option$news">
            <div class="optionTitle$news">
              $nicename
            </div>
            <div class="optionValue$news">
              <input type="password" name="$name" size="$size" value="$value" />
            </div>
$s
          </div>
        </div>
EOT
}

sub checkbox {
 my ($name,$nicename,$size,$func,$default,$valid,$onchange,$description,$data,$http,$gpc)=@_;
 my $Error=checkUpdate($name,$default,$valid,$onchange,$http,$gpc);
 my $news=$Config{ShowNews} && $News{$name} ? ' news' : '';
 my $s1='<input type="checkbox" name="'.$name.'" value="1"';
 $s1.=' checked="checked"' if $Config{$name};
 $s1.=' />';
 my $s2="$Error$description";
 if ($s2) {
  $s2=<<EOT;
            <div class="optionValue$news">
              $s2
            </div>
EOT
 }
 return <<EOT;
        <a name="$name"></a>
        <div class="shadow">
          <div class="option$news">
            <div class="optionTitle$news" style="margin-left: -3px;">
              $s1$nicename
            </div>
$s2
          </div>
        </div>
EOT
}

sub checkbox2 {
 my ($name,$nicename,$size,$func,$default,$valid,$onchange,$description,$data,$http,$gpc)=@_;
 foreach (@{$gpc->{$name.'[]'}}) { $gpc->{$name}+=$_; }
 my $Error=checkUpdate($name,$default,$valid,$onchange,$http,$gpc);
 my $news=$Config{ShowNews} && $News{$name} ? ' news' : '';
 my $s1;
 foreach my $v (sort {$a<=>$b} keys %$data) {
  $s1.='<input type="checkbox" name="'.$name.'[]" value="'.encodeHTMLEntities($v).'"';
  if ($v & $Config{$name}) {
   $s1.=' checked="checked" /><b>'.encodeHTMLEntities($$data{$v});
   $s1.=encodeHTMLEntities(' (default)') if $v & $default;
   $s1.='</b>';
  } else {
   $s1.=' />'.encodeHTMLEntities($$data{$v});
   $s1.=encodeHTMLEntities(' (default)') if $v & $default;
  }
  $s1.='&nbsp;&nbsp;&nbsp;&nbsp;';
 }
 chomp($s1);
 my $s2=$description;
 if ($s2) {
  $s2=<<EOT;
            <div class="optionValue$news" style="margin-top: 5px;">
              $s2
            </div>
EOT
 }
 return <<EOT;
        <a name="$name"></a>
        <div class="shadow">
          <div class="option$news">
            <div class="optionTitle$news">
              $nicename
            </div>
            <div class="optionValue$news">
              $Error
            </div>
            <div class="optionValue$news" style="margin-left: -3px;">
              $s1
            </div>
$s2
          </div>
        </div>
EOT
}

sub radio {
 my ($name,$nicename,$size,$func,$default,$valid,$onchange,$description,$data,$http,$gpc)=@_;
 my $Error=checkUpdate($name,$default,$valid,$onchange,$http,$gpc);
 my $news=$Config{ShowNews} && $News{$name} ? ' news' : '';
 my $s1;
 foreach my $v (sort {$a<=>$b} keys %$data) {
  $s1.='              <input type="radio" name="'.$name.'" value="'.encodeHTMLEntities($v).'"';
  if ($v eq $Config{$name}) {
   $s1.=' checked="checked" /><b>'.encodeHTMLEntities($$data{$v});
   $s1.=encodeHTMLEntities(' (default)') if $v eq $default;
   $s1.='</b>';
  } else {
   $s1.=' />'.encodeHTMLEntities($$data{$v});
   $s1.=encodeHTMLEntities(' (default)') if $v eq $default;
  }
  $s1.="<br />\n";
 }
 chomp($s1);
 my $s2=$description;
 if ($s2) {
  $s2=<<EOT;
            <div class="optionValue$news" style="margin-top: 5px;">
              $s2
            </div>
EOT
 }
 return <<EOT;
        <a name="$name"></a>
        <div class="shadow">
          <div class="option$news">
            <div class="optionTitle$news">
              $nicename
            </div>
            <div class="optionValue$news">
              $Error
            </div>
            <div class="optionValue$news" style="margin-left: -4px;">
$s1
            </div>
$s2
          </div>
        </div>
EOT
}

sub option {
 my ($name,$nicename,$size,$func,$default,$valid,$onchange,$description,$data,$http,$gpc)=@_;
 my $Error=checkUpdate($name,$default,$valid,$onchange,$http,$gpc);
 my $news=$Config{ShowNews} && $News{$name} ? ' news' : '';
 my $s1;
 foreach my $v (sort {$a<=>$b} keys %$data) {
  $s1.='                <option class="'.$$data{$v}.'" value="'.encodeHTMLEntities($v).'"';
  if ($v eq $Config{$name}) {
   $s1.=' style="font-weight: bold" selected="selected" />'.encodeHTMLEntities($$data{$v});
   $s1.=encodeHTMLEntities(' (default)') if $v eq $default;
  } else {
   $s1.=' />'.encodeHTMLEntities($$data{$v});
   $s1.=encodeHTMLEntities(' (default)') if $v eq $default;
  }
  $s1.="\n";
 }
 chomp($s1);
 my $s2=$description;
 if ($s2) {
  $s2=<<EOT;
            <div class="optionValue$news" style="margin-top: 5px;">
              $s2
            </div>
EOT
 }
 return <<EOT;
        <a name="$name"></a>
        <div class="shadow">
          <div class="option$news">
            <div class="optionTitle$news">
              $nicename
            </div>
            <div class="optionValue$news">
              $Error
            </div>
            <div class="optionValue$news">
              <select size="$size" name="$name">
$s1
              </select>
            </div>
$s2
          </div>
        </div>
EOT
}

sub heading {
 my ($description,$nodeId)=@_[4,5,6];
 return <<EOT;
      </div>
      <div onmousedown="toggleDisp('$nodeId')" class="contentHead">
        $description
      </div>
      <div id="$nodeId">
EOT
}

1;