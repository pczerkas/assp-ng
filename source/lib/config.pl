#!/usr/bin/perl

# perl antispam smtp proxy
# (c) John Hanna, John Calvi, Robert Orso, AJ 2004 under the terms of the GPL
# (c) 2006 Przemyslaw Czerkas <przemekc@poczta.onet.pl>

$version='1.2.0';
$modversion=' beta 0';

use bytes; # get rid of annoying 'Malformed UTF-8' messages

%MakeRE=('localDomains' => \&setLDRE,
         'localHostNames' => \&setLHNRE,
         'whiteListedDomains' => \&setWLDRE,
         'blackListedDomains' => \&setBLDRE,
         'BounceSenders' => \&setBSRE,
         'URIBLCCTLDS' => \&setURIBLCCTLDSRE,
         'URIBLwhitelist' => \&setURIBLWLDRE);

%MakeSLRE=('spamLovers' => 'SLRE',
           'hlSpamLovers' => 'HLSLRE',
           'mfSpamLovers' => 'MFSLRE',
           'blSpamLovers' => 'BLSLRE',
           'delayingSpamLovers' => 'DELSLRE',
           'spfSpamLovers' => 'SPFSLRE',
           'rblSpamLovers' => 'RBLSLRE',
           'srsSpamLovers' => 'SRSSLRE',
           'msgVerifySpamLovers' => 'MVSLRE',
           'bombsSpamLovers' => 'BOSLRE',
           'uriblSpamLovers' => 'URIBLSLRE',
           'baysSpamLovers' => 'BSLRE',
           'ratelimitSpamLovers' => 'RLSLRE',
           'spamaddresses' => 'SARE',
           'noProcessing' => 'NPREL',
           'noSenderCheck' => 'NSCRE',
           'ccFilter' => 'CCFRE',
           'LocalAddresses_Flat' => 'LAFRE',
           'noSRS' => 'NSRSRE',
           'noMsgVerify' => 'NMVRE1',
           'noBombScript' => 'NBSRE',
           'noAttachment' => 'NACRE',
           'noURIBL' => 'NURIBLRE');
          
%MakeIPRE=('ispip' => 'ISPRE',
           'allowAdminConnections' => 'AACRE',
           'acceptAllMail' => 'AMRE',
           'noLog' => 'NLOGRE',
           'noGreetDelay' => 'NGDRE',
           'noDelay' => 'NDRE',
           'noSRSBounce' => 'NSRSBRE',
           'noHelo' => 'NHRE',
           'noSPF' => 'NSPFRE',
           'noRBL' => 'NRBLRE',
           'noMsgVerify' => 'NMVRE2',
           'denySMTPConnections' => 'DSMTPCRE',
           'noRateLimit' => 'NRLRE');

$AttachmentBlockLevels={'0'=>'Disabled',
                        '1'=>'Level 1',
                        '2'=>'Level 2',
                        '3'=>'Level 3'};

$HamCollectionOptions={'1'=>'notspam folder',
                       '2'=>'notspam folder & CC',
                       '3'=>'mailok folder',
                       '4'=>'mailok folder & CC',
                       '5'=>'discard',
                       '6'=>'discard & CC'};

$SpamCollectionOptions={'7'=>'spam folder',
                        '8'=>'spam folder & CC',
                        '9'=>'discard',
                        '10'=>'discard & CC',
                        '11'=>'virii folder',
                        '12'=>'virii folder & CC'};

@Config=(
[0,0,0,\&heading,'Network Setup'],
 # except for the heading lines, all config lines have the following:
 #  $name,$nicename,$size,$func,$default,$valid,$onchange,$description,$data
 # name is the variable name that holds the data
 # nicename is a human readable pretty display name (oh how nice!)
 # size is the appropriate input box size
 # func is a function called to render the config item
 # default is the default value
 # valid is a regular expression used to clean and validate the input -- no match is an error and $1 is the desired result
 # onchange is a function to be called when this value is changed -- usually undef; just updating the value is enough
 # group is the heading group belonged to.
 # description is text displayed to help the user figure what to put in the entry
 # data is variable-specific data

 ['myName','My Name',40,\&textinput,'ASSP-nospam','(\S+)',undef,
  'What the program calls itself in the email "received by" header. Usually ASSP-nospam.',undef],
 ['AsAService','As a Service',0,\&checkbox,'','(.*)',undef,
  'In Windows 2000 / NT you can run it as a service; requires <a href="http://www.roth.net/perl/Daemon/" rel="external">win32::daemon</a>. Requires start from the service control panel.',undef],
 ['AsADaemon','As a Daemon',0,\&checkbox,'','(.*)',undef,
  'In Linux/BSD/Unix/OSX fork and close file handles, kinda like "perl assp.pl &amp;" but better. Requires restart.',undef],
 ['listenPort','Listen Port',20,\&textinput,125,'(\S+)',\&configChangeMailPort,
  'On what port should ASSP accept smtp connections? Normally 25. You can supply an interface:port to limit connections.',undef],
 ['listenPort2','Another Listen Port',20,\&textinput,'','(\S*)',\&configChangeMailPort2,
  'Listen for incoming SMTP requests on a second port.<br />
   For those who cannot use SMTP Port 25 outside of their ISP Network,
   or as a dedicated port for VPN purposes.<br />
   You can supply an interface:port to limit connections. For example: 2525 or 127.0.0.2:325',undef],
 ['smtpDestination','SMTP Destination',20,\&textinput,'127.0.0.1:225','(\S*)',undef,
  'The address:port of your message handling system\'s smtp server. For example: 127.0.0.1:125',undef],
 ['smtpAuthServer','SMTP Auth Destination',20,\&textinput,'','(\S*)',undef,
  'Port to connect to when connections arrive on the second Listen Port. If blank all incoming mail will go to the main<br />
   SMTP Destination, the main use is to allow remote / travelling users to make authenticated connections, and therefore<br />
   inject their mail at the SPF-correct point in the network. eg 127.0.0.1:587',undef],
 ['sendNoopInfo','Send NOOP Info',0,\&checkbox,'','(.*)',undef,
  'Checked means you want ASSP to send a "NOOP Connection from $ip" message<br />
   to your SMTP server. (Postfix croaks on this.)',undef],
 ['denySMTPConnections','Deny SMTP Connections*',60,\&textinput,'','(\S*)',\&configMakeIPRe,
  'Connections from these IP addresses will be denied, separate entries by pipes (|). For example: 172.16.|10.',undef],
 ['maxSMTPSessions','Maximum SMTP Sessions',5,\&textinput,0,'(\d+)',undef,
  'The maximum number of SMTP sessions (connections) to handle concurrently.<br />
   This can help if the server is overloading. 20 simultaneous connections is typically enough. 0 = no limit.',undef],
 ['maxSMTPipSessions','Maximum SMTP Sessions/IP',5,\&textinput,0,'(\d+)',undef,
  'The maximum number of SMTP sessions (connections) to handle per IP /24 subnet address concurrently.<br />
   Limit this to prevent DOS attacks, 5 simultaneous connections is typically enough. 0 = no limit.<br />
   Also note that the ISP &amp; accept all mail addresses are excluded from limiting.',undef],
 ['MaxErrors','Max Errors',5,\&textinput,10,'(\d+)',undef,
  'If the SMTP Destination sends $MaxErrors 550s, 501s, 502s ... the connection is dropped.',undef],
 ['SMTPreadtimeout','SMTP Client Read Timeout',5,\&textinput,180,'(\d+)',undef,
  'This sets the SMTP client-side socket read timeout. Defaults to 3 minutes.',undef],
 ['proxyserver','Proxy Server',20,\&textinput,'','(\S*)',undef,
  'Use a Proxy Server for up/downloading greylist etc. Format - interface:port.
   For example: 192.168.0.1:8080',undef],
 ['webAdminPort','Web Admin Port',20,\&textinput,55555,'(\S+)',\&configChangeAdminPort,
  'On what port should ASSP listen for http connections for the web administration interface?<br />
   Changing this will require changing the URL on your browser to reconnect.
   You can supply an interface:port to limit connections.',undef],

[0,0,0,\&heading,'Relaying Control'],
 ['acceptAllMail','Accept All Mail*',60,\&textinput,'','(.*)',\&configMakeIPRe,
  'Allows relaying for these hosts. These hosts also contribute to the whitelist.<br />
   For example: 127.0.0.1|10.|169.254.|172.16.|192.168.',undef],
 ['relayHostFile','Relay Host File',40,\&textinput,'','(.*)',undef,
  'Like Accept All Mail, but this is a file that contains a list of ip addresses (one per line)
   for whom you want to relay mail.<br />
   This is an ABSOLUTE path, not relative to base. For example: /usr/local/assp/relayhosts',undef],
 ['ispip','ISP/Secondary MX Servers*',60,\&textinput,'','(\S*)',\&configMakeIPRe,
  'Enter any addresses that are your ISP or backup MX servers, separated by pipes (|).<br />
   These addresses will (necessarily) bypass Greylist, Maximum SMTP Sessions/IP Limiting,<br />
   Greeting Delay, HELO, Sender, SRS, SPF, RBL, Delaying, URIBL &amp; RateLimit checks.<br />
   For example: 127.0.0.1|10.',undef],
 ['ispgreyvalue','ISP/Secondary MX Grey Value',5,\&textinput,'','(\S*)',undef,
  'It is recommended that for ISP &amp; Secondary MX servers to bypass their greylist values<br />
   For eg. 0.5 (Completely grey). If left blank then the greylist "X" value is used.<br />
   Note: value should be greater than 0 and less than 1, where 0 = never spam &amp; 1 = always spam',undef],
 ['localHostNames','Local Host Names*',60,\&textinput,'','(.*)',\&configMakeRe,
  'Include all IP addresses and aliases for your machine here, separated with |. \'localhost\' and loopback<br />
   interface address are always included. For example: 11.22.33.44|mx.YourDomains.com|here.org',undef],
 ['localDomains','Local Domains*',60,\&textinput,'putYourDomains.com|here.org','(.*)',\&configMakeRe,
  'Addresses in these domains are considered local delivery. Separate addresses with |. Include all subdomains.<br />
   For example: put.YourDomains.com|here.org',undef],
 ['localDomainsFile','Local Domains File',40,\&textinput,'','(.*)',undef,
  'Like Local Domains, but this is a file that contains a list of host names (one per line) for whom you want to accept mail.<br />
   This is an ABSOLUTE path, not relative to base. For example: /usr/local/assp/locals',undef],
 ['defaultLocalDomain','Default Local Domain',40,\&textinput,'','(\S*)',undef,
  'If you want to be able to send mail to local users without a domain name then put the
   default local domain here.<br /> Blank disables this feature. For example: mydomain.com',undef],
 ['PopB4SMTPFile','Pop Before SMTP DB File',40,\&textinput,'','(.*)',undef,
  'Enter the DB database filename of your POP before SMTP implementation with records stored for
   dotted-quad IP addresses<br />
   For example: /etc/mail/popip.db If it\'s got something else, you\'ll need to edit the PopB4SMTP subroutine.',undef],
 ['relayHost','Relay Host',20,\&textinput,'','(\S*)',undef,
  'Your isp\'s mail relayhost (smarthost). For example: mail.isp.com:25<br />
   If you run Exchange/Notes and you want assp to update the nonspam database and the whitelist, then enter your isp\'s<br />
   smtp relay host here. Blank means no relayhost. Only required if clients don\'t deliver through SMTP, or when SRS is enabled.',undef],
 ['relayPort','Relay Port',20,\&textinput,'','(\S*)',\&configChangeRelayPort,
  'Tell your mail server to connect to this port (e.g. 127.0.0.1:225 or 127.0.0.2) as its smarthost / relayhost.
   For example: 225<br /> Note that you\'ll want to keep the relayPort protected from external access by your firewall.<br />
   You can supply an interface:port to limit connections.',undef],
 ['NoRelaying','No Relaying Error',80,\&textinput,'550 5.7.1 Forwarding to remote hosts disabled. This attempt has been logged.','(55\d .*)',undef,
  'SMTP error message to deny relaying.',undef],

[0,0,0,\&heading,'Connection Validation'],
 ['GreetDelay','SMTP Greeting Delay',5,\&textinput,0,'(\d+)',undef,
  'Delay sending 220 greeting message from SMTP server for this many seconds.<br />
   Some spammers use broken software and start transmitting before SMTP server sends the banner.<br />
   If this happens, ASSP terminates the connection with GreetDelayError SMTP error code.<br />
   RFC 2821 specifies a minimum timeout value of 5 minutes for the initial banner.<br />
   Reasonable values are beetween 0 and 90 seconds.',undef],
 ['GreetDelay2','SMTP Greeting Delay for Another Listen Port',5,\&textinput,0,'(\d+)',undef,
  'Delay sending 220 greeting message from SMTP server for this many seconds for client<br />
   connections coming to the second Listen Port.',undef],
 ['noGreetDelay','Don\'t Delay Greeting for these IP\'s*',60,\&textinput,'','(.*)',\&configMakeIPRe,
  'Enter IP addresses for whom you don\'t want to delay greeting, separated by pipes (|).<br />
   For example: 127.0.0.1|192.168.',undef],
 ['GreetDelayError','Reply Message to Refuse E<!--get rid of google autofill-->mail disobeying Greeting Delay',80,\&textinput,'554 SMTP synchronization error. Contact the postmaster of this domain for resolution. This attempt has been logged.','([45]5\d .*|)',undef,
  'SMTP reply message to refuse mail from spontaneous clients. If this field is empty, client connection is simply dropped.',undef],

[0,0,0,\&heading,'Client Validation'],
 ['ValidateHelo','Enable HELO Validation',0,\&checkbox,1,'(.*)',undef,
  'Enable HELO/EHLO Validation. Senders that fail HELO validation will receive SpamError SMTP error code.<br />
   Note: no error is sent if HELO Validation is in test mode.',undef],
 ['HeloPosition','HELO Check Position',1,\&radio,5,'([1-5])',undef,
  '',{'1'=>'early (pre-mailfrom) -- no opt-outs nor failures collecting',
      '2'=>'early (pre-rcpt) -- skips noprocessing, local, whitelisted or authenticated senders',
      '3'=>'normal (pre-data) -- as above, but honours HELO Failures Spamlover addresses',
      '4'=>'late (post-header) -- as above, but failures are collected',
      '5'=>'late (post-body) -- as above, but also body may match npRe/npLwlRe'}],
 ['HeloExtra','Extra HELO Validation',0,\&checkbox2,4,'(.*)',undef,
  'Enable HELO Validation also for noprocessing/whitelisted messages.',
  {'1'=>'noprocessing',
   '2'=>'whitelisted',
   '4'=>'rwl hits'}],
 ['hlSpamRe','Expression to Identify Spam HELO*',80,\&textinput,'\d+[_.-]\d+[_.-]|^[^.]+\.?$|dynamic|ddns|dns.org$','(.*)',\&configCompileRe,
  'If HELO string matches this Perl regular expression message will be considered spam.<br />
   For example: \d+[_.-]\d+[_.-]|^[^.]+\.?$|dynamic|ddns|dns.org$',undef],
 ['HeloForged','Block forged local HELOs',0,\&checkbox,1,'(.*)',undef,
  'Block remote clients that claim to come from our Local Domain/Local Host Name.',undef],
 ['HeloBlacklist','Use the HELO Blacklist',1,\&checkbox,1,'(.*)',undef,
  'Check this box to maintain the list and block HELO strings that were generally used to send spam to you recently.<br />
   You probably want to disable the HELO blacklist in the initial training phase for ASSP.',undef],
 ['HeloMismatch','Block mismatched HELOs',0,\&checkbox,'','(.*)',undef,
  'Check if an A lookup on the HELO/EHLO name matches first 2 octets of the client IP address.',undef],
 ['noHelo','Don\'t Validate HELO for these IP\'s*',60,\&textinput,'','(.*)',\&configMakeIPRe,
  'Enter IP addresses that you don\'t want to be HELO validated, separated by pipes (|).<br />
   For example: 127.0.0.1|192.168.',undef],

[0,0,0,\&heading,'Sender Validation'],
 ['ValidateSender','Enable Sender Validation',0,\&checkbox,'','(.*)',undef,
  'Enable Sender Validation. Senders that fail this test will receive SpamError SMTP error code.<br />
   Note: no error is sent if Sender Validation is in test mode.',undef],
 ['SenderPosition','Sender Check Position',1,\&radio,4,'([1-4])',undef,
  '',{'1'=>'early (pre-rcpt) -- skips noprocessing, local, whitelisted or authenticated senders',
      '2'=>'normal (pre-data) -- as above, but honours Invalid Sender Spamlover addresses',
      '3'=>'late (post-header) -- as above, but failures are collected',
      '4'=>'late (post-body) -- as above, but also body may match npRe/npLwlRe'}],
 ['SenderExtra','Extra Sender Validation',0,\&checkbox2,4,'(.*)',undef,
  'Enable Sender Validation also for noprocessing/whitelisted messages.',
  {'1'=>'noprocessing',
   '2'=>'whitelisted',
   '4'=>'rwl hits'}],
 ['SenderForged','Block forged local senders',0,\&checkbox,1,'(.*)',undef,
  'If activated, each sender address with a local domain is checked against Local Addresses.',undef],
 ['SenderLDAP','Do LDAP lookup for valid sender',0,\&checkbox,'','(.*)',undef,
  'Check local sender address against an LDAP database before accepting the message.<br />
   Note: Checking this requires filling in all values in LDAP Client Options.<br />
   This requires an installed <a href="http://search.cpan.org/~gbarr/perl-ldap-0.33/lib/Net/LDAP.pod" rel="external">NET::LDAP</a> module in PERL.',undef],
 ['SenderMX','Do MX/A record lookup for valid sender domain',0,\&checkbox,1,'(.*)',\&configUpdateSenderMX,
  'Determines whether a DNS record (A or MX) exists for sender address domain.',undef],
 ['SenderBomb','Block senders from bombRe expression',0,\&checkbox,1,'(.*)',undef,
  'Check if sender address matches Expression to Identify Spam Bombs.',undef],
 ['noSenderCheck','Don\'t Validate these Senders*',60,\&textinput,'','(.*)',\&configMakeSLRe,
  'Enter sender addresses that you don\'t want to be validated, separated by pipes (|).<br />
   Valid entry types are as per spamlovers.',undef],

[0,0,0,\&heading,'Recipient Validation'],
 ['LocalAddresses_Flat','Local Addresses*',60,\&textinput,'','(.*)',\&configMakeSLRe,
  'These email addresses are considered local by ASSP. You can list specific addresses (user@mydomain.com),<br />
   addresses at any local domain (user), or entire local domains (@mydomain.com). Separate entries with pipes: |.<br />
   For example: jhanna@thisdomain.com|fhanna|@sillyguys.org or place them in a plain ASCII file one address per line.',undef],
 ['DoRFC822','Validate recipient addresses to conform with RFC 822',0,\&checkbox,1,'(.*)',undef,
  'If activated, each recipient address is checked to conform with the email format defined in RFC 822.<br />
   This requires an installed <a href="http://search.cpan.org/~maurice/Email-Valid-0.15/Valid.pm" rel="external">Email::Valid</a> module in PERL.',undef],
 ['DoLDAP','Do LDAP lookup for valid recipients',0,\&checkbox,'','(.*)',undef,
  'Check recipients against an LDAP database before accepting the message.<br />
   Note: Checking this requires filling in all values in LDAP Client Options.<br />
   This requires an installed <a href="http://search.cpan.org/~gbarr/perl-ldap-0.33/lib/Net/LDAP.pod" rel="external">NET::LDAP</a> module in PERL.',undef],
 ['DetectInvalidRecipient','Detect Invaild-User/No-Such-Account Server Reply',60,\&textinput,'','(.*)',undef,
  'Enter phrase used to detect Invaild-User/No-Such-Account server reply.<br />
   For example: for XMail MTA enter \'550 Mailbox unavailable\'.',undef],
 ['InvalidRecipientError','No-Valid-User Reply',80,\&textinput,'550 5.1.1 Recipient <EMAILADDRESS> not found. Correct the address or contact the postmaster of this domain for resolution. This attempt has been logged.','([25]5\d .*)',undef,
  'SMTP reply for invalid Users. You may reply with a \'fake OK\' by entering \'250 OK - Recipient &lt;EMAILADDRESS&gt;\'<br />
   to confuse address harvesters. The literal EMAILADDRESS (case sensitive) is replaced by the fully qualified<br />
   SMTP recipient (e.g. thisuser@yourcompany.com).',undef],

[0,0,0,\&heading,'LDAP Client Options'],
 ['LDAPHost','LDAP Hosts*',60,\&textinput,'localhost','(.*)',\&configUpdateLDAPHost,
  'Enter the DNS-names or IP addresses of the servers that run the LDAP databases, separated by "|".<br />
   Connection failures are handled in a round-robin manner. For example: localhost|ldap.mydomain.com',undef],
 ['LDAPLogin','LDAP Login',60,\&textinput,'','(.*)',undef,
  'Most LDAP servers require a login and password before they allow queries.<br />
   Enter the DN specification for a user with sufficient permissions here.<br />
   For example: cn=Administrator,cn=Users,DC=yourcompany,DC=com',undef],
 ['LDAPPassword','LDAP Password',20,\&passwdinput,'','(.*)',undef,
 #['LDAPPassword','LDAP Password',20,\&textinput,'','(.*)',undef,
  'Enter the password for the specified LDAP login here.',undef],
 ['LDAPRoot','LDAP Root container',60,\&textinput,'','(.*)',undef,
  'The LDAP lookup will use this container and all sub-containers to match the query.<br />
   For example: DC=yourcompany,DC=com',undef],
 ['LDAPFilter','LDAP Filter',60,\&textinput,'','(\S*)',undef,
  'This filter is used to query the LDAP database. This strongly depends on the LDAP structure.<br />
   The filter must return an entry if the recipient address matches with that of any user.<br />
   The literal EMAILADDRESS (case sensitive) is replaced by the fully qualified SMTP recipient<br />
   (eg. user@domain.com) during the search. For example: (proxyaddresses=smtp:EMAILADDRESS)',undef],

[0,0,0,\&heading,'Noprocessing Options'],
 ['noProcessing','Unprocessed Addresses*',60,\&textinput,'','(.*)',\&configMakeSLRe,
  'Mail solely to or from any of these addresses are ignored by ASSP.<br />
   Like a more efficient version of spamLovers &amp; redlist combined. Valid entry types are as per spamlovers.',undef],
 ['npRe','Expression to Identify No-processing Mail*',80,\&textinput,'','(.*)',\&configCompileRe,
  'If an email header or body matches this Perl regular expression it will pass through unprocessed.',undef],
 ['npLwlRe','Expression to Identify Local/Whitelisted No-processing Mail*',80,\&textinput,'','(.*)',\&configCompileRe,
  'If local or whitelisted email header or body matches this Perl regular expression it will pass through unprocessed.',undef],

[0,0,0,\&heading,'SPAM Lover Options'],
 ['spamLovers','Spam-Lover Addresses*',60,\&textinput,'postmaster','(.*)',\&configMakeSLRe,
  'Spam addressed entirely to spam lovers is not blocked. Mail addressed to both spam lovers and non spam lovers IS blocked.<br />
   Accepts specific addresses (user@domain.com), addresses at local domains (user), or entire local domains (@domain.com).<br />
   Separate entries with pipes: |. For example: jhanna@thisdomain.com|fhanna|@sillyguys.org',undef],
 ['hlSpamLovers','Invalid HELO Spam-Lover Addresses*',60,\&textinput,'','(.*)',\&configMakeSLRe,
  'Invalid HELO Spam-Lover Addresses.',undef],
 ['mfSpamLovers','Invalid Sender Spam-Lover Addresses*',60,\&textinput,'','(.*)',\&configMakeSLRe,
  'Invalid Sender Spam-Lover Addresses.',undef],
 ['blSpamLovers','Blacklisted Spam-Lover Addresses*',60,\&textinput,'','(.*)',\&configMakeSLRe,
  'Blacklisted Spam-Lover Addresses.',undef],
 ['delayingSpamLovers','Delaying Spam-Lover Addresses*',60,\&textinput,'','(.*)',\&configMakeSLRe,
  'Delaying Spam-Lover Addresses.',undef],
 ['spfSpamLovers','SPF Failures Spam-Lover Addresses*',60,\&textinput,'','(.*)',\&configMakeSLRe,
  'SPF Failures Spam-Lover Addresses.',undef],
 ['rblSpamLovers','RBL Failures Spam-Lover Addresses*',60,\&textinput,'','(.*)',\&configMakeSLRe,
  'RBL Failures Spam-Lover Addresses.',undef],
 ['srsSpamLovers','Not SRS Signed Bounces Spam-Lover Addresses*',60,\&textinput,'','(.*)',\&configMakeSLRe,
  'Not SRS Signed Bounces Spam-Lover Addresses.',undef],
 ['msgVerifySpamLovers','Message Verification Spam-Lover Addresses*',60,\&textinput,'','(.*)',\&configMakeSLRe,
  'Message Verification Spam-Lover Addresses.',undef],
 ['bombsSpamLovers','Spam Bombs &amp; Scripting Spam-Lover Addresses*',60,\&textinput,'','(.*)',\&configMakeSLRe,
  'Spam Bombs &amp; Scripting Spam-Lover Addresses.',undef],
 ['uriblSpamLovers','URIBL Failures Spam-Lover Addresses*',60,\&textinput,'','(.*)',\&configMakeSLRe,
  'URIBL Failures Spam-Lover Addresses.',undef],
 ['baysSpamLovers','Bayesian Spam-Lover Addresses*',60,\&textinput,'','(.*)',\&configMakeSLRe,
  'Bayesian Spam-Lover Addresses.',undef],
 ['ratelimitSpamLovers','RateLimit Spam-Lover Addresses*',60,\&textinput,'','(.*)',\&configMakeSLRe,
  'RateLimit Spam-Lover Addresses.',undef],

[0,0,0,\&heading,'Whitelist Options'],
 ['whiteListedDomains','Whitelisted Domains*',60,\&textinput,'sourceforge.net','(.*)',\&configMakeRe,
  'Domains from which you want to receive all mail<br />
   Your ISP, domain registration, mail list servers, stock broker, or other key business partners might be good candidates.<br />
   Note this matches the end of the address, so if you don\'t want to match subdomains then include the @.<br />
   Note that buy.com would also match spambuy.com but .buy.com won\'t match buy.com.<br />
   DO NOT put your local domains on this list. For example: sourceforge.net|@google.com|.buy.com',undef],
 ['redRe','Expression to Identify Redlisted Mail*',80,\&textinput,'file:data/lists/redre.txt','(.*)',\&configCompileRe,
  'If an email header matches this Perl regular expression it will be considered redlisted. For example: \\[autoreply\\]',undef],
 ['NotGreedyWhitelist','Only the envelope-sender is added/compared to the whitelist',0,\&checkbox,'','(.*)',undef,
  'Normal operation includes addresses in the FROM, SENDER, REPLY-TO, ERRORS-TO, or LIST-* header fields.<br />
   This allows nearly all list email to be whitelisted. Check this option to disable this.',undef],
 ['WhitelistLocalOnly','Only local or authenticated users contribute to the whitelist.',0,\&checkbox,'','(.*)',undef,
  'Normal operation allows all local, authenticated, or whitelisted users to add to the whitelist.<br />
   Check this box to not allow whitelisted users to add to the whitelist.',undef],
 ['MaxWhitelistDays','Max Whitelist Days',5,\&textinput,90,'(\d+)',undef,
  'This is the number of days an address will be kept on the whitelist without any email to/from this address.',undef],
 ['ValidateRWL','Enable Realtime Whitelist Validation',0,\&checkbox,1,'(.*)',\&configUpdateRWL,
  'Senders that pass RWL validation will be considered whitelisted.',undef],
 ['RWLServiceProvider','RWL Service Providers*',60,\&textinput,'file:data/lists/RWLServiceProvider.txt','(.*)',\&configUpdateRWLSP,
  'Domain Names of RBLs to use separated by "|". Defaults are...<br />
   query.bondedsender.org|dnswl.junkemailfilter.com|exemptions.ahbl.org|iadb.isipp.com|hul.habeas.com',undef],
 ['RWLmaxreplies','Maximum Replies',5,\&textinput,5,'(\d*)',\&configUpdateRWLMR,
  'A reply is affirmative or negative reply from a RWL.<br />
   The RWL module will wait for this number of replies (negative or positive) from the RWLs listed under Service Provider<br />
   for up to the Maximum Time below. This number should be equal to or less than the number of RWL Service Providers<br />
   listed to allow for randomly unavailable RWLs',undef],
 ['RWLminhits','Minimum Hits',5,\&textinput,3,'(\d*)',\&configUpdateRWLMH,
  'A hit is an affirmative response from a RWL.<br />
   The RWL module will check all of the RWLs listed under Service Provider, and flag the email<br />
   with a RWL pass flag if equal to or more than this number of RWLs return a postive whitelisted response.<br />
   This number should be less than or equal to Maximum Replies above and greater than 0',undef],
 ['RWLmaxtime','Maximum Time',5,\&textinput,10,'(\d*)',undef,
  'This sets the maximum time to spend on each message performing RWL checks',undef],
 ['noRWL','Don\'t Validate RWL for these IP\'s*',60,\&textinput,'','(.*)',\&configMakeIPRe,
  'Enter IP addresses that you don\'t want to be RWL validated, separated by pipes (|).<br />
   For example: 127.0.0.1|192.168.',undef],

 ['DelayWL','Whitelisted Delaying',0,\&checkbox,'','(.*)',undef,
  'Enable Delaying for whitelisted senders also.',undef],

[0,0,0,\&heading,'SPAM Control'],
 ['blackListedDomains','Blacklisted Domains*',60,\&textinput,'','(.*)',\&configMakeRe,
  'Domains from which you always want to reject mail, they only send you spam. For example: spam.net|xxxpics.com',undef],
 ['spamaddresses','Spam Trap Addresses*',60,\&textinput,'put|your@spambucket.com|addresses|@here.org','(.*)',\&configMakeSLRe,
  'Mail to any of these users at are always spam unless from someone on the whitelist;<br />
   @domain.com makes the whole domain a spam domain. A username without domain will register across all local domains.',undef],
 ['SpamError','Spam Error',80,\&textinput,'550 5.7.7 Unsolicited email not allowed. If you have received this message in error, contact the postmaster of this domain for resolution. This attempt has been logged.','(55\d .*|)',undef,
  'SMTP error message to reject Invalid HELO, Blacklisted domain, Spam Trap and Bayesian spam.<br />
   If this field is empty, client connection is simply dropped.',undef],

[0,0,0,\&heading,'Delaying Options'],
 ['EnableDelaying','Enable Delaying',0,\&checkbox,'','(.*)',undef,
  'Enable Greylisting (to avoid name clash let\'s call it Delaying) as described at <a href="http://projects.puremagic.com/greylisting/" rel="external">projects.puremagic.com/greylisting</a>.<br />
   It\'s a new method of blocking significant amounts of spam at the mailserver level, but without resorting to heavyweight<br />
   statistical analysis or other heuristical approaches.',undef],
 ['DelayEmbargoTime','Embargo Time',5,\&textinput,5,'(\d+)',undef,
  'Enter the number of minutes for which delivery, related with new \'triplet\' (IP address of the sending<br />
   host + mail from + rcpt to), is refused with a temporary failure. Default is 5 minutes.',undef],
 ['DelayWaitTime','Wait Time',5,\&textinput,28,'(\d+)',undef,
  'Enter the number of hours to wait for delivery attempts related with recognised \'triplet\'; delivery is accepted<br />
   immediately and the \'tuplet\' (IP address of the sending host + sender\'s domain) is whitelisted. Default is 28 hours.',undef],
 ['DelayExpiryTime','Expiry Time',5,\&textinput,36,'(\d+)',undef,
  'Enter the number of days for which whitelisted \'tuplet\' is considered valid. Default is 36 days.',undef],
 ['DelayUseNetblocks','Use IP Netblocks',0,\&checkbox,1,'(.*)',undef,
  'Perform the IP address checks of the sending host based on the /24 subnet it is at rather than the specific IP.<br />
   This feature may be useful for legitimate mail systems that shuffle messages among SMTP clients between retransmissions.',undef],
 ['DelayNormalizeVERPs','Normalize VERP Addresses',0,\&checkbox,1,'(.*)',undef,
  'Some mailing lists (such as Ezmlm) try to track bounces to individual mails, rather than just individual recipients,<br />
   which creates a variation on the VERP method where each email has it\'s own unique envelope sender. Since the automatic<br />
   whitelisting that is built into Delaying depends on the envelope addresses for subsequent emails being the same,<br />
   the delay filter will attempt to normalize the unique sender addresses, when this option is checked.',undef],
 ['DelayExpireOnSpam','Expire Spamming Whitelisted Tuplets',0,\&checkbox,1,'(.*)',undef,
  'If a whitelisted \'tuplet\' is ever associated with spam, viri, failed rbl, spf etc, it is deleted from the whitelist.<br />
   This renews the temporary embargo for subsequent mail involving the tuplet.',undef],
 ['noDelay','Don\'t Delay these IP\'s*',60,\&textinput,'file:data/lists/nodelay.txt','(.*)',\&configMakeIPRe,
  'Enter IP addresses that you don\'t want to be delayed, separated by pipes (|). There are misbehaving MTAs that will<br />
   not be able to get a legitimate email through a greylisting server because they do not try again later. An INCOMPLETE<br />
   list of such mailers is available at <a href="http://cvs.puremagic.com/viewcvs/greylisting/schema/whitelist_ip.txt" rel="external">cvs.puremagic.com/viewcvs/greylisting/schema/whitelist_ip.txt</a>.<br />
   When using mentioned list remember to add trailing dots in IP addresses which specify subnets (eg. 192.168 -> 192.168. ).<br />
   For example: 127.0.0.1|192.168.',undef],
 ['DelayError','Reply Message to Refuse Delayed E<!--get rid of google autofill-->mail',80,\&textinput,'451 4.7.1 Please try again later','(45\d .*)',undef,
  'SMTP reply message to refuse delayed mail.',undef],

[0,0,0,\&heading,'SPF Options'],
 ['ValidateSPF','Enable SPF Validation',0,\&checkbox,1,'(.*)',undef,
  'Enable Sender Policy Framework Validation as described at <a href="http://spf.pobox.com" rel="external">spf.pobox.com</a>.<br />
   This requires an installed <a href="http://spf.pobox.com/downloads.html" rel="external">Mail::SPF::Query</a> module in PERL.<br />
   Senders that fail SPF validation will receive SPFError SMTP error code.<br />
   Note: no error is sent if SPF is in test mode.',undef],
 ['SPFPosition','SPF Check Position',1,\&radio,4,'([1-4])',undef,
  '',{'1'=>'early (pre-rcpt) -- skips noprocessing, local, whitelisted or authenticated senders',
      '2'=>'normal (pre-data) -- as above, but honours SPF Failures Spamlover addresses',
      '3'=>'late (post-header) -- as above, but failures are collected',
      '4'=>'late (post-body) -- as above, but also body may match npRe/npLwlRe'}],
 ['SPFExtra','Extra SPF Validation',0,\&checkbox2,4,'(.*)',undef,
  'Enable SPF Validation also for noprocessing/whitelisted messages.',
  {'1'=>'noprocessing',
   '2'=>'whitelisted',
   '4'=>'rwl hits'}],
 ['LocalPolicySPF','Local SPF Policy',60,\&textinput,'v=spf1 a/24 mx/24 ptr ~all','(.*)',undef,
  'If the sending domain does not publish its own SPF Records a local policy can be defined.<br />
   The default is v=spf1 a/24 mx/24 ptr ~all',undef],
 ['noSPF','Don\'t Validate SPF for these IP\'s*',60,\&textinput,'','(.*)',\&configMakeIPRe,
  'Enter IP addresses that you don\'t want to be SPF validated, separated by pipes (|).<br />
   For example: 127.0.0.1|192.168.',undef],
 ['DebugSPF','Enable SPF Debug output to ASSP Logfile',0,\&checkbox,'','(.*)',undef,
  'Enables verbose debugging of SPF queries within the Mail::SPF::Query module.',undef],
 ['SPFError','Reply Message to refuse failed SPF E<!--get rid of google autofill-->mail',80,\&textinput,'550 5.7.1 COMMENT. Contact the postmaster of this domain for resolution. This attempt has been logged.','([45]5\d .*|)',undef,
  'SMTP reply message to refuse failed SPF mail. The literal COMMENT (case sensitive) is replaced<br />
   by the SPF failure decription. If this field is empty, client connection is simply dropped.',undef],

[0,0,0,\&heading,'RBL Options'],
 ['ValidateRBL','Enable Realtime Blacklist Validation',0,\&checkbox,1,'(.*)',\&configUpdateRBL,
  'Senders that fail RBL validation will receive RBLError SMTP error code.<br />
   Note: no error is sent if RBL is in test mode.',undef],
 ['RBLPosition','RBL Check Position',1,\&radio,6,'([1-6])',undef,
  '',{'1'=>'early (on-connect) -- no opt-outs nor failures collecting',
      '2'=>'early (pre-banner) -- as above, but after Greeting Delay',
      '3'=>'early (pre-rcpt) -- skips noprocessing, local, whitelisted or authenticated senders',
      '4'=>'normal (pre-data) -- as above, but honours RBL Failures Spamlover addresses',
      '5'=>'late (post-header) -- as above, but failures are collected',
      '6'=>'late (post-body) -- as above, but also body may match npRe/npLwlRe'}],
 ['RBLExtra','Extra RBL Validation',0,\&checkbox2,4,'(.*)',undef,
  'Enable RBL Validation also for noprocessing/whitelisted messages.',
  {'1'=>'noprocessing',
   '2'=>'whitelisted',
   '4'=>'rwl hits'}],
 ['RBLServiceProvider','RBL Service Providers*',60,\&textinput,'file:data/lists/RBLServiceProvider.txt','(.*)',\&configUpdateRBLSP,
  'Domain Names of RBLs to use separated by "|". Defaults are...<br />
   bl.spamcop.net|cbl.abuseat.org|sbl-xbl.spamhaus.org|dnsbl.njabl.org|list.dsbl.org|dnsbl.sorbs.net|opm.blitzed.org|dynablock.njabl.org',undef],
 ['RBLmaxreplies','Maximum Replies',5,\&textinput,6,'(\d*)',\&configUpdateRBLMR,
  'A reply is affirmative or negative reply from a RBL.<br />
   The RBL module will wait for this number of replies (negative or positive) from the RBLs listed under Service Provider<br />
   for up to the Maximum Time below. This number should be equal to or less than the number of RBL Service Providers<br />
   listed to allow for randomly unavailable RBLs',undef],
 ['RBLmaxhits','Maximum Hits',5,\&textinput,3,'(\d*)',\&configUpdateRBLMH,
  'A hit is an affirmative response from a RBL.<br />
   The RBL module will check all of the RBLs listed under Service Provider, and flag the email<br />
   with a RBL failure flag if equal to or more than this number of RBLs return a postive blacklisted response.<br />
   This number should be less than or equal to Maximum Replies above and greater than 0',undef],
 ['RBLmaxtime','Maximum Time',5,\&textinput,10,'(\d*)',undef,
  'This sets the maximum time to spend on each message performing RBL checks',undef],
 ['noRBL','Don\'t Validate RBL for these IP\'s*',60,\&textinput,'','(.*)',\&configMakeIPRe,
  'Enter IP addresses that you don\'t want to be RBL validated, separated by pipes (|).<br />
   For example: 127.0.0.1|192.168.',undef],
 ['RBLError','Reply Message to refuse failed RBL E<!--get rid of google autofill-->mail',80,\&textinput,'550 5.7.1 Blacklisted by RBLNAME Contact the postmaster of this domain for resolution. This attempt has been logged.','([45]5\d .*|)',undef,
  'SMTP reply message to refuse failed RBL mail. The literal RBLNAME (case sensitive) is replaced<br />
   by the names of RBLs with negative response. If this field is empty, client connection is simply dropped.',undef],

[0,0,0,\&heading,'SRS Options'],
 ['EnableSRS','Enable Sender Rewriting Scheme',0,\&checkbox,'','(.*)',\&configUpdateSRS,
  'Enable Sender Rewriting Scheme as described at <a href="http://spf.pobox.com/srs.html" rel="external">spf.pobox.com/srs.html</a>.<br />
   This requires an installed <a href="http://spf.pobox.com/downloads.html" rel="external">Mail::SRS</a> module in PERL.<br />
   You should use SRS if your message handling system forwards email for domains with published spf records.<br />
   Note that you have to setup the outgoing path (Relay Host &amp; Port) to let ASSP see and rewrite your outgoing traffic.',undef],
 ['SRSAliasDomain','Alias Domain',40,\&textinput,'thisdomain.com','(.*)',\&configUpdateSRSAD,
  'SPF requires the SMTP client IP to match the envelope sender (return-path). When a message is forwarded through<br />
   an intermediate server, that intermediate server may need to rewrite the return-path to remain SPF compliant.<br />
   For example: thisdomain.com',undef],
 ['SRSSecretKey','Secret Key',20,\&passwdinput,'','(.*)',\&configUpdateSRSSK,
  'A key for the cryptographic algorithms -- Must be at least 5 characters long.',undef],
 ['SRSTimestampMaxAge','Maximum Timestamp Age',5,\&textinput,21,'(\d+)',undef,
  'Enter the maximum number of days for which a timestamp is considered valid. Default is 21 days.',undef],
 ['SRSHashLength','Hash Length',5,\&textinput,4,'(\d+)',undef,
  'The number of bytes of base64 encoded data to use for the cryptographic hash.<br />
   More is better, but makes for longer addresses which might exceed the 64 character length suggested by RFC2821.<br />
   This defaults to 4, which gives 4 x 6 = 24 bits of cryptographic information, which means that a spammer will have<br />
   to make 2^24 attempts to guarantee forging an SRS address.',undef],
 ['noSRS','Don\'t Rewrite these Addresses*',60,\&textinput,'','(.*)',\&configMakeSLRe,
  'Don\'t Rewrite these Addresses. Valid entry types are as per spamlovers.',undef],
 ['SRSValidateBounce','Enable Bounce Recipient Validation',0,\&checkbox,1,'(.*)',undef,
  'Bounce messages that fail reverse SRS validation (but not a valid SMTP probes)<br />
   will receive SRSBounceError SMTP error code.',undef],
 ['BounceSenders','Bounce Senders*',60,\&textinput,'postmaster|mailer-daemon','(.*)',\&configMakeRe,
  'Envelope sender addresses treatead as bounce origins. Null sender (&lt;&gt;) is always included.<br />
   Accepts specific addresses (postmaster@domain.com), usernames (mailer-daemon), or entire domains<br />
   (@bounces.domain.com). Separate entries with pipes: |. For example: postmaster|mailer-daemon',undef],
 ['SRSRewriteToHeader','Rewrite To: Header in bouce messages',0,\&checkbox,1,'(.*)',undef,
  'Reverse SRS validated bounce messages have mangled To: header. When enabled ASSP will try<br />
   to unwind To: header to original email address.',undef],
 ['noSRSBounce','Don\'t Validate Bounces from these IP\'s*',60,\&textinput,'','(.*)',\&configMakeIPRe,
  'Enter IP addresses that you don\'t want to validate bounces from, separated by pipes (|).<br />
   For example: 127.0.0.1|192.168.',undef],
 ['SRSBounceError','Reply Message to refuse invalid bounce E<!--get rid of google autofill-->mail',80,\&textinput,'550 5.7.5 Bounce address not SRS signed. Contact the postmaster of this domain for resolution. This attempt has been logged.','([45]5\d .*|)',undef,
  'SMTP reply message to refuse bounce messages that fail reverse SRS validation.<br />
   If this field is empty, client connection is simply dropped.',undef],

[0,0,0,\&heading,'Message Verification'],
 ['EnableMsgVerify','Enable Message Verification',0,\&checkbox,'','(.*)',undef,
  'Enable Message Verification. Connections that fail Message Verification will receive SpamError SMTP error code.<br />
   Note: no error is sent if Message Verification is in test mode.',undef],
 ['MsgVerifyExtra','Extra Message Verification',0,\&checkbox2,4,'(.*)',undef,
  'Enable Message Verification also for noprocessing/whitelisted messages.',
  {'1'=>'noprocessing',
   '2'=>'whitelisted',
   '4'=>'rwl hits'}],
 ['MsgVerifyHeaders','Validate message headers to conform with RFC 2822',0,\&checkbox,1,'(.*)',undef,
  'If activated, message headers are checked to conform with the format defined in <a href="http://rfc.net/rfc2822.html#s2.2." rel="external">RFC 2822</a>.<br /><br />
   Note: RFC 2822 specifies rules for forming Internet messages. It does not allow the use of characters with codes above<br />
   127 to be used directly (non-encoded) in mail headers, it also prohibits NUL and bare CR. For the sake of usability<br />
   ASSP looses the first requirement and allows 8-bit characters within the header field values (many MTA\'s do this).',undef],
 ['MsgVerifyLineLength','Maximum Line Length',5,\&textinput,1000,'(\d+)',undef,
  'Enter maximum message line length. To allow messages with oversized lines set this to 0.<br /><br />
   Note: <a href="http://rfc.net/rfc2822.html#s2.1.1." rel="external">RFC 2822</a> states that each line MUST be no more than 998 characters excluding the CRLF.',undef],
 ['noMsgVerify','Don\'t Verify Messages from these Addresses/IP\'s*',60,\&textinput,'','(.*)',\&configMakeSLIPRe,
  'Don\'t Verify Messages from these Addresses. Valid entry types are as per spamlovers or IP addresses.',undef],

[0,0,0,\&heading,'Spam Bombs &amp; Scripting'],
 ['bombRe','Expression to Identify Spam Bombs*',80,\&textinput,'','(.*)',\&configCompileRe,
  'It is possible for a spammer to create 1000s of messages that appear to be from your domain.<br />
   When these messages bounce, the bounces come to you. You can use this feature to block those messages.<br />
   Leave this blank to disable the feature. For example: images/ad12\.gif',undef],
 ['scriptRe','Expression to Identify Mobile Scripts*',80,\&textinput,'','(.*)',\&configCompileRe,
  'Spam emails may contain mobile scripting code, eg activex and java. You can use this feature to block those messages.<br />
   Leave this blank to disable the feature. For example: \&lt;applet|\&lt;embed|\&lt;iframe|\&lt;object|\&lt;script|onmouseover|javascript:',undef],
 ['noBombScript','Don\'t Check Messages from these Addresses*',60,\&textinput,'','(.*)',\&configMakeSLRe,
  'Don\'t detect spam boms or scripts in messages from these addresses. Valid entry types are as per spamlovers.',undef],
 ['bombError','Spam Bomb Error',80,\&textinput,'550 5.7.7 Spam-bomb phrase detected. Rephrase your message and send again, or contact the postmaster of this domain for resolution. This attempt has been logged.','(55\d .*|)',undef,
  'SMTP error message to reject spam bombs. If this field is empty, client connection is simply dropped.',undef],
 ['scriptError','Script Error',80,\&textinput,'550 5.7.7 HTML scripting code not allowed. Resend with scripts removed, or contact the postmaster of this domain for resolution. This attempt has been logged.','(55\d .*|)',undef,
  'SMTP error message to reject scripts. If this field is empty, client connection is simply dropped.',undef],

[0,0,0,\&heading,'Attachment Control'],
 ['BlockExes','External Attachment Blocking',1,\&option,0,'(\d*)',undef,
  'This determines the level of attachment protection to provide for external mail.',$AttachmentBlockLevels],
 ['BlockWLExes','Whitelisted &amp; Local Attachment Blocking',1,\&option,0,'(\d*)',undef,
  'This determines the level of attachment protection for whitelisted &amp; local senders.',$AttachmentBlockLevels],
 ['BlockNPExes','NoProcessing Attachment Blocking',1,\&option,0,'(\d*)',undef,
  'This determines the level of attachment protection for no processing senders.',$AttachmentBlockLevels],
 ['BadAttachL1','Level 1 Blocked File Extensions',60,\&textinput,'exe|scr|pif|vb[es]|js|jse|ws[fh]|sh[sb]|lnk|bat|cmd|com|ht[ab]','(.*)',\&configUpdateBadAttachL1,
  'This regular expression is used to identify Level 1 attachments that should be blocked.<br />
   Separate entries with a pipe |. The dot . is assumed to preceed these, so don\'t include it. For example:<br />
   ad[ep]|asx|ba[st]|chm|cmd|com|cpl|crt|dbx|exe|hlp|ht[ab]|in[fs]|isp|js|jse|lnk|<br />
   md[abez]|mht|ms[cipt]|nch|pcd|pif|prf|reg|sc[frt]|sh[bs]|vb|vb[es]|wms|ws[cfh]',undef],
 ['BadAttachL2','Level 2 Blocked File Extensions',60,\&textinput,'','(.*)',\&configUpdateBadAttachL2,
  'This regular expression is used to identify Level 2 attachments that should be blocked.<br />
   Level 2 already includes all blocked extensions from Level 1. For example:<br />
   (ad[ep]|asx|ba[st]|chm|cmd|com|cpl|crt|dbx|exe|hlp|ht[ab]|in[fs]|isp|js|jse|lnk|<br />
   md[abez]|mht|ms[cipt]|nch|pcd|pif|prf|reg|sc[frt]|sh[bs]|vb|vb[es]|wms|ws[cfh]).zip',undef],
 ['BadAttachL3','Level 3 Blocked File Extensions',60,\&textinput,'zip','(.*)',\&configUpdateBadAttachL3,
  'This regular expression is used to identify Level 3 attachments that should be blocked.<br />
   Level 3 includes Level 2 and Level 1. For example: zip|url',undef],
 ['noAttachment','Don\'t Check Messages from these Addresses*',60,\&textinput,'','(.*)',\&configMakeSLRe,
  'Don\'t detect bad attachments in messages from these addresses. Valid entry types are as per spamlovers.',undef],
 ['AttachmentError','Attachment Error',80,\&textinput,'550 5.7.7 Executable attachments not allowed. Compress any attachments before mailing, or contact the postmaster of this domain for resolution. This attempt has been logged.','(55\d .*|)',undef,
  'SMTP error message to reject attachments. If this field is empty, client connection is simply dropped.',undef],

[0,0,0,\&heading,'URIBL Options'],
 ['ValidateURIBL','Enable URI Blocklist Validation',0,\&checkbox,1,'(.*)',\&configUpdateURIBL,
  'Enable URI Blocklist as described at <a href="http://www.uribl.com/about.shtml" rel="external">www.uribl.com/about.shtml</a>.<br />
   Messages that fail URIBL validation will receive URIBLError SMTP error code.<br />
   Note: no error is sent if URIBL is in test mode.',undef],
 ['URIBLExtra','Extra URIBL Validation',0,\&checkbox2,4,'(.*)',undef,
  'Enable URIBL Validation also for noprocessing/whitelisted messages.',
  {'1'=>'noprocessing',
   '2'=>'whitelisted',
   '4'=>'rwl hits'}],
 ['URIBLServiceProvider','URIBL Service Providers*',60,\&textinput,'file:data/lists/URIBLServiceProvider.txt','(.*)',\&configUpdateURIBLSP,
  'Domain Names of URIBLs to use separated by "|". Defaults are: multi.surbl.org|multi.uribl.com',undef],
 ['URIBLCCTLDS','URIBL Country Code TLDs*',60,\&textinput,'file:data/lists/URIBLCCTLDS.txt','(.*)',\&configMakeRe,
  'List of <a href="http://spamcheck.freeapp.net/two-level-tlds" rel="external">country code TLDs</a> used to determine the base domain of the uri.',undef],
 ['URIBLmaxuris','Maximum URIs',5,\&textinput,200,'(\d*)',undef,
  'Messages with more than this number of uri\'s in the body will receive URIBLPolicyError SMTP error code.<br />
   This prevents DOS attacks, enter 0 to disable feature (not recommended).',undef],
 ['URIBLmaxdomains','Maximum Unique Domain URIs',10,\&textinput,5,'(\d*)',undef,
  'Messages with more than this number of unique domain uri\'s in the body will receive URIBLPolicyError SMTP error code.<br />
   This prevents DOS attacks, enter 0 to disable feature (not recommended).',undef],
 ['URIBLNoObfuscated','Disallow Obfuscated URIs',0,\&checkbox,1,'(.*)',undef,
  'When enabled messages with obfuscated uri\'s in the body will receive URIBLPolicyError SMTP error code.',undef],
 ['URIBLmaxreplies','Maximum Replies',5,\&textinput,2,'(\d*)',\&configUpdateURIBLMR,
  'A reply is affirmative or negative reply from a URIBL.<br />
   The URIBL module will wait for this number of replies (negative or positive) from the URIBLs listed under Service Provider<br />
   for up to the Maximum Time below. This number should be equal to or less than the number of URIBL Service Providers<br />
   listed to allow for randomly unavailable URIBLs.',undef],
 ['URIBLmaxhits','Maximum Hits',5,\&textinput,1,'(\d*)',\&configUpdateURIBLMH,
  'A hit is an affirmative response from a URIBL.<br />
   The URIBL module will check all of the URIBLs listed under Service Provider,<br />
   and flag the email with a URIBL failure flag if more than this number of URIBLs return a postive blacklisted response.<br />
   This number should be less than or equal to Maximum Replies above and greater than 0.',undef],
 ['URIBLmaxtime','Maximum Time',5,\&textinput,10,'(\d*)',undef,
  'This sets the maximum time to spend on each message performing URIBL checks.',undef],
 ['URIBLwhitelist','Whitelisted URIBL Domains*',60,\&textinput,'doubleclick.net','(.*)',\&configMakeRe,
  'This prevents specific domains from being checked by URIBL module.',undef],
 ['noURIBL','Don\'t Check Messages from these Addresses*',60,\&textinput,'','(.*)',\&configMakeSLRe,
  'Don\'t validate URIBL when messages come from these addresses. Valid entry types are as per spamlovers.',undef],
 ['URIBLPolicyError','URIBL Policy Abuse Reply',80,\&textinput,'550 5.7.1 Message rejected by domain policy. Contact the postmaster of this domain for resolution. This attempt has been logged.','(55\d .*|)',undef,
  'SMTP reply message to refuse URIBL policy abuse. If this field is empty, client connection is simply dropped.',undef],
 ['URIBLError','Reply Message to refuse failed URIBL E<!--get rid of google autofill-->mail',80,\&textinput,'550 5.7.1 Blacklisted by URIBLNAME Contact the postmaster of this domain for resolution. This attempt has been logged.','([45]5\d .*|)',undef,
  'SMTP reply message to refuse failed URIBL mail. The literal URIBLNAME (case sensitive) is replaced<br />
   by the names of URIBLs with negative response. If this field is empty, client connection is simply dropped.',undef],

[0,0,0,\&heading,'Virus Control'],
 ['AvUseClamAV','Use ClamAV Engine',0,\&checkbox,'','(.*)',undef,
  'Scan for viruses using <a href="http://www.clamav.net/" rel="external">ClamAV\'s</a> clamd daemon.',undef],
 ['AvDestination','Clamd Destination',20,\&Avtextinput,'127.0.0.1:3310','(\S*)',undef,
  'The address:port of clamd daemon service. For example: 127.0.0.1:3310',undef],
 ['Avmaxtime','Maximum Time',5,\&Avtextinput,120,'(\d*)',undef,
  'This sets the maximum time to spend on each message performing AV checks.<br />
   Other sessions are not blocked during AV scanning.',undef],
 ['AvPath','Path to Anti-virus Databases',40,\&Avtextinput,'','(.*)',undef,
  'The directory path to your anti-virus databases, uses ASSP\'s base if left blank. For example: /usr/share/clamav/db',undef],
 ['AvDbs','List of Anti-virus Signature Database Files',60,\&Avtextinput,'main.db,daily.db','(.*)',undef,
  'A comma (no space!) separated list of virus signature files. Blank this out to disable virus scanning.<br />
   For example: main.db,daily.db. These files are available on http://assp.sourceforge.net',undef],
 ['AVBytes','AV Bytes',10,\&Avtextinput,100000,'(\d*)',undef,
  'How many bytes of the message will be Virus scanned? For example: 100000<br />
   Leave Blank to scan entire email which results in a significant performance penalty on large attachments.<br />
   Most virus signatures match in the first 20-100K of the message.',undef],
 ['Avlocal','Virus Scan Local',0,\&checkbox,1,'(.*)',undef,
  'Check this box to scan local users email as well.',undef],
 ['AvError','Error Message to Reject Infected E<!--get rid of google autofill-->mail',80,\&textinput,'550 5.7.7 \'$infection\' virus detected. Disinfect and resend, or contact the postmaster of this domain for resolution. This attempt has been logged.','(55\d .*|)',undef,
  'SMTP error message to reject infected mail. The string $infection is replaced with the name of the detected virus.<br />
   If this field is empty, client connection is simply dropped.',undef],

[0,0,0,\&heading,'Bayesian Options'],
 ['whiteRe','Expression to Identify Non-Spam*',80,\&textinput,'','(.*)',\&configCompileRe,
  'If an incoming email matches this Perl regular expression it will be considered non-spam.<br />
   For example: Secret Ham Password|307\D{0,3}730\D{0,3}4[12]\d\d<br />
   For help writing regular expressions click <a href="http://www.perlmonks.org/index.pl?node=perlre" rel="external">here</a>.
   Note that flags are "si" and the header as well as body is scanned.<br />
   Some things you might include here are your office phone number or street address, spam rarely includes these details.',undef],
 ['blackRe','Expression to Identify Spam*',80,\&textinput,'http://[\\w\\.]+@|\w<[a-z0-9]+[abcdfghjklmnpqrstuvwxyz0-9]{4}[a-z0-9]*>|subject: [^\\n]*     \S','(.*)',\&configCompileRe,
  'If an incoming email that\'s not local or whitelisted matches this Perl regular expression it will be considered spam.<br />
   May match text from the body or header of the email. For example: penis|virgin|X-Priority: 1',undef],
 ['WhitelistOnly','Reject All But Whitelisted Mail',0,\&checkbox,'','(.*)',undef,
  'Check this if you don\'t want Bayesian filtering and want to reject all mail from anyone not whitelisted.<br />
   Note: this turns the redlist into a blacklist.',undef],

[0,0,0,\&heading,'TestMode Options'],
 ['hlTestMode','Helo Test Mode',0,\&checkbox,1,'(.*)',undef,
  'If set then all Invalid HELO messages are delivered.',undef],
 ['mfTestMode','Sender Test Mode',0,\&checkbox,1,'(.*)',undef,
  'If set then all Invalid Sender messages are delivered.',undef],
 ['blTestMode','Blacklist Test Mode',0,\&checkbox,1,'(.*)',undef,
  'If set then all Blacklisted messages are delivered.',undef],
 ['sbTestMode','Spam Trap Test Mode',0,\&checkbox,1,'(.*)',undef,
  'If set then all Spam Trap messages are delivered.',undef],
 ['spfTestMode','SPF Test Mode',0,\&checkbox,1,'(.*)',undef,
  'If set then all SPF failed messages are delivered.',undef],
 ['rblTestMode','RBL Test Mode',0,\&checkbox,1,'(.*)',undef,
  'If set then all RBL failed messages are delivered.',undef],
 ['srsTestMode','SRS Test Mode',0,\&checkbox,1,'(.*)',undef,
  'If set then all SRS failed (not signed) bounces are delivered.',undef],
 ['malformedTestMode','Malformed Test Mode',0,\&checkbox,1,'(.*)',undef,
  'If set then all malformed messages are delivered.',undef],
 ['uriblTestMode','URIBL Test Mode',0,\&checkbox,1,'(.*)',undef,
  'If set then all URIBL failed messages are delivered.',undef],
 ['baysTestMode','Bayesian Test Mode',0,\&checkbox,1,'(.*)',undef,
  'If set then all Bayesian Spam messages are delivered.',undef],

[0,0,0,\&heading,'RateLimit Options'],
 ['EnableRateLimit','Enable RateLimit',0,\&checkbox,'','(.*)',undef,
  'Enable per-client rate-limiting and auto-blocking.<br /><br />
   Note: Parameters accept data in the following format: Limit/Interval/BlockTime.<br />
   Times may be entered as (s)econds, (m)inutes, (h)ours or (d)ays.<br />
   For example: \'3/10m/0\' means \'limit this event to 3 per 10 minutes, don\'t block client<br />
   (reply with RateLimitError if rate limit exceeded)\' whereas \'5/3h/1d\' means \'limit this event<br />
   to 5 per 3 hours, block client for 1 day (reply with RateLimitBlockedError if rate limit exceeded)\'.',undef],
 ['RateLimitPosition','RateLimit Block Position',1,\&radio,4,'([1-4])',undef,
  'This sets the stage at which clients are blocked due to RateLimit block rules.',
  {'1'=>'early (on-connect) -- no opt-outs possible',
   '2'=>'early (pre-banner) -- as above, but after Greeting Delay',
   '3'=>'early (pre-rcpt) -- skips noprocessing, local, whitelisted or authenticated senders',
   '4'=>'normal (pre-data) -- as above, but honours RateLimit Spamlover addresses'}],
 ['RateLimitExtra','Extra RateLimit',0,\&checkbox2,4,'(.*)',undef,
  'Enable RateLimit also for noprocessing/whitelisted messages.',
  {'1'=>'noprocessing',
   '2'=>'whitelisted',
   '4'=>'rwl hits'}],
 ['RateLimitUseNetblocks','Use IP Netblocks',0,\&checkbox,'','(.*)',undef,
  'Perform the IP address checks of the sending host based on the /24 subnet it is at rather than the specific IP.',undef],

 ['RateLimitClient','Enable RateLimit for Client Validation',0,\&checkbox,'','(.*)',undef,
  'Enable RateLimit events for client validation.',undef],
 ['RLIBTclientHeloValidated','Accepted Validated Helos Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="positive">Accepted Validated Helos</span> rate limit.',undef],
 ['RLIBTclientHeloUnchecked','Accepted Unchecked Helos Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="positive">Accepted Unchecked Helos</span> rate limit.',undef],
 ['RLIBTclientHeloForged','Rejected Forged Helos Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative">Rejected Forged Helos</span> rate limit.',undef],
 ['RLIBTclientHeloBlacklisted','Rejected Blacklisted Helos Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative">Rejected Blacklisted Helos</span> rate limit.',undef],
 ['RLIBTclientHeloMismatch','Rejected Mismatched Helos Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative">Rejected Mismatched Helos</span> rate limit.',undef],
 ['RLIBTclientHeloSpam','Rejected Spam Helos Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative">Rejected Spam Helos</span> rate limit.',undef],

 ['RateLimitSender','Enable RateLimit for Sender Validation',0,\&checkbox,'','(.*)',undef,
  'Enable RateLimit events for sender validation.',undef],
 ['RLIBTsenderValidatedLocal','Accepted Local Validated Senders Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="positive">Accepted Local Validated Senders</span> rate limit.',undef],
 ['RLIBTsenderUncheckedLocal','Accepted Local Unchecked Senders Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="positive">Accepted Local Unchecked Senders</span> rate limit.',undef],
 ['RLIBTsenderWhitelisted','Accepted Remote Whitelisted Senders Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="positive">Accepted Remote Whitelisted Senders</span> rate limit.',undef],
 ['RLIBTsenderValidatedRemote','Accepted Remote Validated Senders Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="positive">Accepted Remote Validated Senders</span> rate limit.',undef],
 ['RLIBTsenderUncheckedRemote','Accepted Remote Unchecked Senders Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="positive">Accepted Remote Unchecked Senders</span> rate limit.',undef],
 ['RLIBTsenderUnprocessed','Noprocessed Senders Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="positive">Noprocessed Senders</span> rate limit.',undef],
 ['RLIBTsenderForged','Rejected Local Forged Senders Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative">Rejected Local Forged Senders</span> rate limit.',undef],
 ['RLIBTsenderBombLocal','Rejected Local BombRe Senders Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative">Rejected Local BombRe Senders</span> rate limit.',undef],
 ['RLIBTsenderNoMX','Rejected Remote Nonexistent MX Senders Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative">Rejected Remote Nonexistent MX Senders</span> rate limit.',undef],
 ['RLIBTsenderBombRemote','Rejected Remote BombRe Senders Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative">Rejected Remote BombRe Senders</span> rate limit.',undef],

 ['RateLimitRcpt','Enable RateLimit for Recipients Validation',0,\&checkbox,'','(.*)',undef,
  'Enable RateLimit events for recipients validation.',undef],
 ['RLIBTrcptValidated','Accepted Local Validated Recipients Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="positive">Accepted Local Validated Recipients</span> rate limit.',undef],
 ['RLIBTrcptUnchecked','Accepted Local Unchecked Recipients Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="positive">Accepted Local Unchecked Recipients</span> rate limit.',undef],
 ['RLIBTrcptSpamLover','Accepted Local Spam-Lover Recipients Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="positive">Accepted Local Spam-Lover Recipients</span> rate limit.',undef],
 ['RLIBTrcptWhitelisted','Accepted Remote Whitelisted Recipients Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="positive">Accepted Remote Whitelisted Recipients</span> rate limit.',undef],
 ['RLIBTrcptNotWhitelisted','Accepted Remote Not Whitelisted Recipients Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="positive">Accepted Remote Not Whitelisted Recipients</span> rate limit.',undef],
 ['RLIBTrcptUnprocessed','Noprocessed Recipients Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="positive">Noprocessed Recipients</span> rate limit.',undef],
 ['RLIBTrcptDelayed','Rejected Local Delayed Recipients Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative">Rejected Local Delayed Recipients</span> rate limit.',undef],
 ['RLIBTrcptDelayedLate','Rejected Local Delayed (Late) Recipients Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative">Rejected Local Delayed (Late) Recipients</span> rate limit.',undef],
 ['RLIBTrcptDelayedExpired','Rejected Local Delayed (Expired) Recipients Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative">Rejected Local Delayed (Expired) Recipients</span> rate limit.',undef],
 ['RLIBTrcptEmbargoed','Rejected Local Embargoed Recipients Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative">Rejected Local Embargoed Recipients</span> rate limit.',undef],
 ['RLIBTrcptSpamBucket','Rejected Local Spam Trap Recipients Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative">Rejected Local Spam Trap Recipients</span> rate limit.',undef],

 ['RateLimitPassed','Enable RateLimit for Passed Messages',0,\&checkbox,'','(.*)',undef,
  'Enable RateLimit events for ham and passed spam messages.',undef],
 ['RLIBTmsgAnyHam','Any Ham Messages Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="positive"><b>Any Ham Messages</b></span> rate limit. This includes the following events:<br />
   <a href="/#RLIBTnoprocessing">No processing messages</a>, <a href="/#RLIBTlocals">Local messages</a>,
   <a href="/#RLIBTwhites">Whitelisted messages</a>, <a href="/#RLIBTreds">Redlisted messages</a>,
   <a href="/#RLIBTbhams">Bayesian non spam messages</a>.',undef],
 ['RLIBTnoprocessing','No Processing Messages Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="positive"><b>No processing messages</b></span> rate limit.',undef],
 ['RLIBTlocals','Local Messages Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="positive"><b>Local messages</b></span> rate limit.',undef],
 ['RLIBTwhites','Whitelisted Messages Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="positive"><b>Whitelisted messages</b></span> rate limit.',undef],
 ['RLIBTreds','Redlisted Messages Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="positive"><b>Redlisted messages</b></span> rate limit.',undef],
 ['RLIBTbhams','Bayesian Non Spam Messages Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="positive"><b>Bayesian non spam messages</b></span> rate limit.',undef],
 ['RLIBTmsgAnyPassedSpam','Any Passed Spam Messages Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="neutral"><b>Any Passed Spam Messages</b></span> rate limit. This includes the following events:<br />
   <a href="/#RLIBTspamlover">Spamlover spam messages</a>, <a href="/#RLIBTtestspams">Testmode spam messages</a>.',undef],
 ['RLIBTspamlover','Spamlover Messages Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="neutral"><b>Spamlover spam messages</b></span> rate limit.',undef],
 ['RLIBTtestspams','Testmode Messages Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="neutral"><b>Testmode spam messages</b></span> rate limit.',undef],

 ['RateLimitBlocked','Enable RateLimit for Blocked Messages',0,\&checkbox,1,'(.*)',undef,
  'Enable RateLimit events for blocked messages.',undef],
 ['RLIBTmsgAnyBlockedSpam','Any Blocked Spam Messages Limit/Interval/BlockTime',10,\&RLIBTtextinput,'1/1h/1d','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative"><b>Any Blocked Spam Messages</b></span> rate limit.<br />
   Depending on testmode/spamlovers configuration this may include the following events:<br />
   <a href="/#RLIBThelolisted">Invalid HELO messages</a>, <a href="/#RLIBTsenderfails">Invalid Sender messages</a>,
   <a href="/#RLIBTblacklisted">Blacklisted Domain messages</a>, <a href="/#RLIBTmsgNoSRSBounce">SRS Failure (not signed bounces) messages</a>,
   <a href="/#RLIBTspambucket">Spam Trap messages</a>, <a href="/#RLIBTspffails">SPF Failure messages</a>,
   <a href="/#RLIBTrblfails">RBL Failure messages</a>, <a href="/#RLIBTmalformed">Malformed messages</a>,
   <a href="/#RLIBTuriblfails">URIBL Failure messages</a>, <a href="/#RLIBTbombs">Spam Bomb messages</a>,
   <a href="/#RLIBTscripts">Scripted messages</a>, <a href="/#RLIBTviri">Blocked Attachment messages</a>,
   <a href="/#RLIBTviridetected">Virus-infected messages</a>, <a href="/#RLIBTbspams">Bayesian spam messages</a>.',undef],
 ['RLIBThelolisted','Invalid HELO Messages Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative"><b>Invalid HELO messages</b></span> rate limit.',undef],
 ['RLIBTsenderfails','Invalid Sender Messages Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative"><b>Invalid Sender messages</b></span> rate limit.',undef],
 ['RLIBTblacklisted','Blacklisted Domain Messages Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative"><b>Blacklisted Domain messages</b></span> rate limit.',undef],
 ['RLIBTmsgNoSRSBounce','SRS Failure Messages Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative"><b>SRS Failure (not signed bounces) messages</b></span> rate limit.',undef],
 ['RLIBTspambucket','Spam Trap Messages Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative"><b>Spam Trap messages</b></span> rate limit.',undef],
 ['RLIBTspffails','SPF Failure Messages Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative"><b>SPF Failure messages</b></span> rate limit.',undef],
 ['RLIBTrblfails','RBL Failure Messages Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative"><b>RBL Failure messages</b></span> rate limit.',undef],
 ['RLIBTmalformed','Malformed Messages Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative"><b>Malformed messages</b></span> rate limit.',undef],
 ['RLIBTuriblfails','URIBL Failure Messages Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative"><b>URIBL Failure messages</b></span> rate limit.',undef],
 ['RLIBTbombs','Spam Bomb Messages Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative"><b>Spam Bomb messages</b></span> rate limit.',undef],
 ['RLIBTscripts','Script Messages Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative"><b>Scripted messages</b></span> rate limit.',undef],
 ['RLIBTviri','Blocked Attachment Messages Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative"><b>Blocked Attachment messages</b></span> rate limit.',undef],
 ['RLIBTviridetected','Virus Messages Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative"><b>Virus-infected messages</b></span> rate limit.',undef],
 ['RLIBTbspams','Bayesian Spam Messages Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative"><b>Bayesian spam messages</b></span> rate limit.',undef],

 ['RateLimitEmailInterface','Enable RateLimit for Email Interface',0,\&checkbox,'','(.*)',undef,
  'Enable RateLimit events for email interface messages.',undef],
 ['RLIBTrcptReportSpam','E<!--get rid of google autofill-->mail Spam Reports Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="positive">Email Spam Reports</span> rate limit.',undef],
 ['RLIBTrcptReportHam','E<!--get rid of google autofill-->mail Ham Reports Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="positive">Email Ham Reports</span> rate limit.',undef],
 ['RLIBTrcptReportWhitelistAdd','E<!--get rid of google autofill-->mail Whitelist Additions Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="positive">Email Whitelist Additions</span> rate limit.',undef],
 ['RLIBTrcptReportWhitelistRemove','E<!--get rid of google autofill-->mail Whitelist Deletions Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="positive">Email Whitelist Deletions</span> rate limit.',undef],
 ['RLIBTrcptReportRedlistAdd','E<!--get rid of google autofill-->mail Redlist Additions Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="positive">Email Redlist Additions</span> rate limit.',undef],
 ['RLIBTrcptReportRedlistRemove','E<!--get rid of google autofill-->mail Redlist Deletions Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="positive">Email Redlist Deletions</span> rate limit.',undef],

 ['RateLimitMisc','Enable RateLimit for other events',0,\&checkbox,1,'(.*)',undef,
  'Enable RateLimit for all the other events.',undef],
 ['RLIBTrcptNonexistent','Rejected Local Nonexistent Recipients Limit/Interval/BlockTime',10,\&RLIBTtextinput,'1/1h/1d','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative">Rejected Local Nonexistent Recipients</span> rate limit.',undef],
 ['RLIBTmsgNoRcpt','Empty Recipient Rejects Limit/Interval/BlockTime',10,\&RLIBTtextinput,'1/1h/1d','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative">Empty Recipient rejects</span> rate limit.',undef],
 ['RLIBTrcptRelayRejected','Rejected Remote Relay Attempts Limit/Interval/BlockTime',10,\&RLIBTtextinput,'1/1h/1d','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative">Rejected Remote Relay Attempts &amp; Malformed Addresses</span> rate limit.',undef],
 ['RLIBTmsgMaxErrors','Max Errors Exceeded Messages Limit/Interval/BlockTime',10,\&RLIBTtextinput,'1/1h/1d','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative">Max Errors Exceeded messages</span> rate limit.',undef],
 ['RLIBTmsgEarlytalker','Earlytalkers Rejects Limit/Interval/BlockTime',10,\&RLIBTtextinput,'1/1h/1d','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative">Earlytalkers rejects</span> rate limit.',undef],
 ['RLIBTmsgDelayed','Delayed Messages Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative">Delayed messages</span> rate limit.',undef],
 ['RLIBTmsgAborted','Aborted Messages Limit/Interval/BlockTime',10,\&RLIBTtextinput,'0/0/0','(\d+\/\d+[smhd]?\/\d+[smhd]?)',\&configUpdateRLIBT,
  '<span class="negative">Aborted Messages</span> rate limit.',undef],

 ['noRateLimit','Don\'t RateLimit these IP\'s*',60,\&textinput,'','(.*)',\&configMakeIPRe,
  'Enter IP addresses that you don\'t want to be rate-limited, separated by pipes (|).',undef],
 ['RateLimitError','RateLimit Error',80,\&textinput,'451 4.7.1 Rate limit exceeded. Contact the postmaster of this domain for resolution. This attempt has been logged.','([45]5\d .*|)',undef,
  'SMTP error message to reject rate-limited sessions. If this field is empty, client connection is simply dropped.',undef],
 ['RateLimitBlockedError','RateLimit Blocked Error',80,\&textinput,'550 5.7.7 Client blocked. This attempt has been logged.','(55\d .*|)',undef,
  'SMTP error message to reject blocked connections. If this field is empty, client connection is simply dropped.',undef],

[0,0,0,\&heading,'Postprocessing Options'],
 ['spamSubject','Prepend Spam Subject',20,\&textinput,'','(.*)',\&configMakeSubTagRe,
  'If TestMode and message is spam, spamSubject gets prepended to the subject of the email.<br />
   The literal TAG (case sensitive) is replaced by verbose spam description. For example: [SPAM-TAG]',undef],
 ['spamSubjectSL','Prepend Spam Subject for Spamlovers',0,\&checkbox,1,'(.*)',undef,
  'If set and message is spam for spamlover, spamSubject gets prepended to the subject of the email.',undef],
 ['AddSpamHeader','Add Spam Header',0,\&checkbox,1,'(.*)',undef,
  'Adds a line to the email header "X-Assp-Spam: YES" if the message is spam.',undef],
 ['AddSpamReasonHeader','Add X-Assp-Spam-Reason Header',0,\&checkbox,1,'(.*)',undef,
  'Adds a line to the email header "X-Assp-Spam-Reason: " explaining why the message is spam.',undef],
 ['AddRWLHeader','Add X-Assp-Received-RWL Header',0,\&checkbox,1,'(.*)',undef,
  'Add X-Assp-Received-RWL header to header of all emails processed by RWL.',undef],
 ['DelayAddHeader','Add X-Assp-Delay Header',0,\&checkbox,1,'(.*)',undef,
  'Add X-Assp-Delay header to header of all delayed or whitelisted emails.',undef],
 ['AddSPFHeader','Add X-Assp-Received-SPF Header',0,\&checkbox,1,'(.*)',undef,
  'Add Received-SPF header to header of all emails processed by SPF.',undef],
 ['AddRBLHeader','Add X-Assp-Received-RBL Header',0,\&checkbox,1,'(.*)',undef,
  'Add X-Assp-Received-RBL header to header of all emails processed by RBL.',undef],
 ['AddURIBLHeader','Add X-Assp-Received-URIBL Header',0,\&checkbox,1,'(.*)',undef,
  'Add X-Assp-Received-URIBL header to header of all emails processed by URIBL.',undef],
 ['AddSpamProbHeader','Add X-Assp-Spam-Prob Header',0,\&checkbox,1,'(.*)',undef,
  'Adds a line to the email header "X-Assp-Spam-Prob: 0.0123" Probs range from 0 to +1 where > 0.6 = spam.',undef],
 ['NoExternalSpamProb','Block Outgoing X-Assp-Spam-Prob header',0,\&checkbox,1,'(.*)',undef,
  'Check this box if you don\'t want your X-Assp-Spam-Prob header on external mail<br />
   Note this means mail from local users to local users will also be missing the header.',undef],
 ['AddSpamAnalysisHeader','Add X-Assp-Spam-Analysis Header',0,\&checkbox,1,'(.*)',undef,
  'Adds X-Assp-Spam-Analysis header to header of all emails processed by Bayesian filter.',undef],


[0,0,0,\&heading,'Collection Options'],
 ['npColl','No Processing',1,\&option,5,'([1-6])',undef,
  'Where to store no processing emails.<br /><br />
   Note: Messages may undergo multiple spam tests. At any stage of processing, the test will be performed only if its assigned<br />
   collection value or severity (testmode, spamlover vs blocking) is greater than the value aquired so far by the message.',$HamCollectionOptions],
 ['localColl','Local or Whitelisted Ham',1,\&option,1,'([1-6])',undef,
  'Where to store local emails.',$HamCollectionOptions],
 ['whiteColl','Whitelisted Ham',1,\&option,1,'([1-6])',undef,
  'Where to store whitelisted emails.',$HamCollectionOptions],
 ['redColl','Redlisted',1,\&option,3,'([1-6])',undef,
  'Where to store redlisted emails.',$HamCollectionOptions],
 ['baysNonSpamColl','Bayesian Non Spam',1,\&option,3,'([1-6])',undef,
  'Where to store Bayesian non spam (message ok) emails.<br />
   Recommended: \'mailok folder\' (prevents false negatives from corrupting corpus)',$HamCollectionOptions],
 ['baysSpamColl','Bayesian Spams',1,\&option,8,'([7-9]|1[0-2])',undef,
  'Where to store Bayesian spam emails.',$SpamCollectionOptions],
 ['spamHeloColl','Spam Helos',1,\&option,8,'([7-9]|1[0-2])',undef,
  'Where to store spam helo emails.',$SpamCollectionOptions],
 ['mfFailColl','Sender Failures',1,\&option,8,'([7-9]|1[0-2])',undef,
  'Where to store sender failure emails.',$SpamCollectionOptions],
 ['blDomainColl','Blacklisted Domains',1,\&option,8,'([7-9]|1[0-2])',undef,
  'Where to store blacklisted domain emails.',$SpamCollectionOptions],
 ['SRSFailColl','SRS Failures',1,\&option,8,'([7-9]|1[0-2])',undef,
  'Where to store SRS Failure (not signed bounces) spam emails.',$SpamCollectionOptions],
 ['spamBucketColl','Spam Trap Addresses',1,\&option,9,'([7-9]|1[0-2])',undef,
  'Where to store has spam trap address emails.',$SpamCollectionOptions],
 ['SPFFailColl','SPF Failures',1,\&option,8,'([7-9]|1[0-2])',undef,
  'Where to store SPF Failure spam emails.',$SpamCollectionOptions],
 ['RBLFailColl','RBL Failures',1,\&option,8,'([7-9]|1[0-2])',undef,
  'Where to store RBL Failure spam emails.',$SpamCollectionOptions],
 ['malformedColl','Malformed Messages',1,\&option,12,'([7-9]|1[0-2])',undef,
  'Where to store malformed messages.',$SpamCollectionOptions],
 ['URIBLFailColl','URIBL Failures',1,\&option,8,'([7-9]|1[0-2])',undef,
  'Where to store URIBL Failure spam emails.',$SpamCollectionOptions],
 ['spamBombColl','Spam Bombs',1,\&option,8,'([7-9]|1[0-2])',undef,
  'Where to store spam bombs.',$SpamCollectionOptions],
 ['scriptColl','Scripts',1,\&option,9,'([7-9]|1[0-2])',undef,
  'Where to store scripted emails.',$SpamCollectionOptions],
 ['wlAttachColl','Whitelisted Blocked Attachments',1,\&option,11,'([7-9]|1[0-2])',undef,
  'Where to store Whitelisted blocked attachments.',$SpamCollectionOptions],
 ['npAttachColl','No Processing Blocked Attachments',1,\&option,11,'([7-9]|1[0-2])',undef,
  'Where to store no processing blocked attachments.',$SpamCollectionOptions],
 ['extAttachColl','External Blocked Attachments',1,\&option,11,'([7-9]|1[0-2])',undef,
  'Where to store external blocked attachments.',$SpamCollectionOptions],
 ['viriColl','Viruses',1,\&option,11,'([7-9]|1[0-2])',undef,
  'Where to store virus-infected emails.',$SpamCollectionOptions],
 ['freqNonSpam','Non Spam Collecting Frequency',5,\&textinput,1,'(\d*)',\&configUpdateLog2,
  'Store every n\'th non spam message. Eg. if you set the value to 10 then every 10th message is collected.<br />
   These frequency settings are for ASSP users with a mature installtion who experience heavy mail or spam volumes.<br />
   Enter a larger value if the non spam corpus is being refreshed too quickly. Default Value = 1, collect every message.',undef],
 ['freqSpam','Spam Collecting Frequency',5,\&textinput,1,'(\d*)',\&configUpdateLog3,
  'Store every n\'th spam message. The same as for non spam but helps prevent spam corpuses being skewed by flooding.<br />
   It is recommended that this be set depending on spam volume. Default value = 1, collect every message.',undef],
 ['MaxFiles','Max Files',10,\&textinput,14009,'(\d+)',undef,
  'This is the maximum number of files to keep in each collection<br />
   It\'s actually less than this -- files get a random number between 1 and $MaxFiles.',undef],
 ['FilesDistribution','Files Distribution',10,\&textinput,1,'(0\.\d?[1-9]+|1)',undef,
  'This governs how file names are chosen in each collection. If set to 1, names are uniformly distributed.<br />
   If set between 0.01 and 0.99, names distribution is exponential -- files get lower numbers more frequently.<br />
   This prevents from corpus being refreshed too quickly, especially when MaxFiles is set to low value (ex. 3000)<br />
   Recommended: 1 or 0.05-0.5',undef],
 ['NoMaillog','Don\'t collect mail',0,\&checkbox,'','(.*)',undef,
  'Check this if you\'re using Whitelist-Only and don\'t care to save mail to build the Bayesian database.',undef],

[0,0,0,\&heading,'Email Interface'],
 ['EmailInterfaceOk','Enable Email Interface',0,\&checkbox,1,'(.*)',undef,
  'Checked means that you want to ASSP to intercept and parse mail to the following usernames at any localdomains.<br />
   If you are using RelayHost and RelayPort see
   <a href="http://assp.sourceforge.net/fom/cache/45.html" rel="external">this note</a>.',undef],
 ['EmailSpam','Report Spam Address',20,\&textinput,'assp-spam','(.*)',undef,
  'Any mail sent by local/authenticated users to this username will be interpreted as a spam report.<br />
   No mail is delivered! For example: assp-spam<br /><br />
   <input type="button" value=" Edit spamreport.txt file" onClick="popFileEditor(\'data/reports/spamreport.txt\',2);">',undef],
 ['EmailHam','Report not-Spam Address',20,\&textinput,'assp-notspam','(.*)',undef,
  'Any mail sent by local/authenticated users to this username will be interpreted as a false-positive report.<br />
   No mail is delivered! For example: assp-notspam<br /><br />
   <input type="button" value=" Edit notspamreport.txt file" onClick="popFileEditor(\'data/reports/notspamreport.txt\',2);">',undef],
 ['EmailWhitelistAdd','Add to Whitelist Address',20,\&textinput,'assp-white','(.*)',undef,
  'Any mail sent by local/authenticated users to this username will be interpreted as a request<br />
   to add addresses to the whitelist. No mail is delivered! For example: assp-white<br /><br />
   <input type="button" value=" Edit whitereport.txt file" onClick="popFileEditor(\'data/reports/whitereport.txt\',2);">',undef],
 ['EmailWhitelistRemove','Remove from Whitelist Address',20,\&textinput,'assp-notwhite','(.*)',undef,
  'Any mail sent by local/authenticated users to this username will be interpreted as a request<br />
   to remove addresses from the whitelist. No mail is delivered! For example: assp-notwhite<br /><br />
   <input type="button" value=" Edit whiteremovereport.txt file" onClick="popFileEditor(\'data/reports/whiteremovereport.txt\',2);">',undef],
 ['EmailRedlistAdd','Add to Redlist Address',20,\&textinput,'assp-red','(.*)',undef,
  'Any mail sent by local/authenticated users to this username will be interpreted as a request<br />
   to add addresses to the redlist. No mail is delivered! For example: assp-red<br /><br />
   <input type="button" value=" Edit redreport.txt file" onClick="popFileEditor(\'data/reports/redreport.txt\',2);">',undef],
 ['EmailRedlistRemove','Remove from Redlist Address',20,\&textinput,'assp-notred','(.*)',undef,
  'Any mail sent by local/authenticated users to this username will be interpreted as a request<br />
   to remove addresses from the redlist. No mail is delivered! For example: assp-notred<br /><br />
   <input type="button" value=" Edit redremovereport.txt file" onClick="popFileEditor(\'data/reports/redremovereport.txt\',2);">',undef],
 ['NoHaikuCorrection','Don\'t reply to Spam/Not-Spam Reports',0,\&checkbox,'','(.*)',undef,
  'Check this option to suppress email confirmations for spam/not-spam reports sent via the email interface.',undef],
 ['NoHaikuWhitelist','Don\'t reply to Add to/Remove from Whitelist Reports',0,\&checkbox,'','(.*)',undef,
  'Check this option to suppress email confirmations for Add to/Remove from Whitelist reports sent via the email interface.',undef],
 ['NoHaikuRedlist','Don\'t reply to Add to/Remove from Redlist Reports',0,\&checkbox,'','(.*)',undef,
  'Check this option to suppress email confirmations for Add to/Remove from Redlist reports sent via the email interface.',undef],
 ['EmailFrom','From Address for E<!--get rid of google autofill-->mail',40,\&textinput,'ASSP <>','(.+)',undef,
  'Email sent from ASSP acknowledging your submissions will be sent from this address.<br />
   Some mailers don\'t like the default setting. For example: ASSP &lt;&gt; or Mail Administrator
   &lt;mailadmin@mydomain.com&gt;',undef],

[0,0,0,\&heading,'CC Options'],
 ['ccHam','Address to CC Ham',40,\&textinput,'','(.*)',undef,
  'If you put an email address in this box ASSP will try to deliver a copy of ham email to this address.<br />
   This is the forward ham feature. For example: spammeister@mydomain.com',undef],
 ['ccSpam','Address to CC Spam',40,\&textinput,'','(.*)',undef,
  'If you put an email address in this box ASSP will try to deliver a copy of spam email to this address.<br />
   This is the forward spam feature. For example: spammeister@mydomain.com',undef],
 ['ccBlocked','Address to CC Blocked Spam',40,\&textinput,'','(.*)',undef,
  'If you put an email address in this box ASSP will try to deliver a copy of blocked spam email to this address.<br />
   This is the forward blocked spam feature. For example: spammeister@mydomain.com',undef],
 ['ccHamSubject','Prepend CC Ham Subject',20,\&textinput,'[NOTSPAM-TAG]','(.*)',\&configMakeSubTagRe,
  'If message is not spam ccHamSubject gets prepended to the subject of the CC\'d email.<br />
   The literal TAG (case sensitive) is replaced by verbose ham description. For example: [NOTSPAM-TAG]',undef],
 ['ccSpamSubject','Prepend CC Spam Subject',20,\&textinput,'[SPAM-TAG]','(.*)',\&configMakeSubTagRe,
  'If message is spam, ccSpamSubject gets prepended to the subject of the CC\'d email.<br />
   The literal TAG (case sensitive) is replaced by verbose spam description. For example: [SPAM-TAG]',undef],
 ['ccBlockedSubject','Prepend CC Blocked Spam Subject',20,\&textinput,'[BLOCKED-TAG]','(.*)',\&configMakeSubTagRe,
  'If message is blocked spam, ccBlockedSubject gets prepended to the subject of the CC\'d email.<br />
   The literal TAG (case sensitive) is replaced by verbose spam description. For example: [BLOCKED-TAG]',undef],
 ['ccFilter','CC Senders/Recipients Filter*',60,\&textinput,'','(.*)',\&configMakeSLRe,
  'CC emails addressed only to or from any of these addresses. Valid entry types are as per spamlovers.<br />
   Leave this blank to disable feature.',undef],

[0,0,0,\&heading,'File Paths'],
 ['base','Directory Base',40,\&textinput,'.','',undef,
  'All paths are relative to this folder.<br />
   <b>Note: this must be changed as a command line parameter and is displayed here for reference only.</b>',undef],
 ['spamlog','Spam Collection',40,\&textinput,'corpus/spam','(\S+)',undef,
  'The folder to save the collection of spam emails. For example: corpus/spam',undef],
 ['notspamlog','Not-spam Collection',40,\&textinput,'corpus/notspam','(\S+)',undef,
  'The folder to save the collection of not-spam emails. For example: corpus/notspam',undef],
 ['incomingOkMail','External OK mail',40,\&textinput,'','(.*)',undef,
  'The folder to save Bayesian non-spam (message ok). Leave this blank to not save these files (default).<br />
   If you want to keep copies of OK mail then put in a directory name. For example: corpus/okmail',undef],
 ['viruslog','Virus Collection',40,\&textinput,'','(.*)',undef,
  'The folder to save virii, blocked attachments and scripting. Leave this blank to not save these files (default).<br />
   If you want to keep copies of blocked content then put in a directory name. For example: corpus/virii',undef],
 ['correctedspam','False-negative Collection',40,\&textinput,'corpus/errors/spam','(\S+)',undef,
  'Spam that got through -- counts double. For example: corpus/errors/spam',undef],
 ['correctednotspam','False-positive Collection',40,\&textinput,'corpus/errors/notspam','(\S+)',undef,
  'Good mail that was listed as spam, count 4x. For example: corpus/errors/notspam',undef],
 ['maillogExt','Extension for Mail Files',20,\&textinput,'.eml','(\S*)',undef,
  'Enter the file extension (include the period) you want appended to the mail files in the mail collections.<br />
   Leave it blank for no extension. For Example: .eml',undef],
 ['spamdb','Spam Bayesian Database File',40,\&textinput,'data/spamdb','(\S+)',undef,
  'The output file from rebuildspamdb.pl.',undef],
 ['whitelistdb','E<!--get rid of google autofill-->mail Whitelist Database File',40,\&textinput,'data/whitelist','(\S+)',undef,
  'The file with the whitelist.',undef],
 ['redlistdb','E<!--get rid of google autofill-->mail Redlist Database File',40,\&textinput,'data/redlist','(\S+)',undef,
  'The file with the redlist.',undef],
 ['dnsbl','DNS Blacklist Database File',40,\&textinput,'','(\S*)',undef,
  'The file with the current DNSBL -- make this blank if you don\'t use it.',undef],
 ['greylist','Greylist Database',40,\&textinput,'data/greylist','(\S*)',undef,
  'The file with the current greylist database -- make this blank if you don\'t use it.',undef],
 ['delaydb','Delaying Database',40,\&textinput,'data/delaydb','(\S*)',undef,
  'The file with the delay database.',undef],
 ['ratelimitdb','RateLimit Database',40,\&textinput,'data/ratelimitdb','(\S*)',undef,
  'The file with the ratelimit database.',undef],
 ['corpusdb','Corpus Cache Database',40,\&textinput,'data/corpusdb','(\S*)',undef,
  'The file with the corpus cache database.',undef],
 ['logfile','ASSP Logfile',40,\&textinput,'logs/maillog.txt','(.*)',\&configChangeLogfile,
  'Blank if you don\'t want a log file. Change it to logs/maillog.log if you don\'t want auto rollover/rotation.',undef],
 ['slogfile','ASSP Sessions Logfile',40,\&textinput,'logs/sesslog.txt','(.*)',\&configChangeSlogfile,
  'Blank if you don\'t want sessions log file. Change it to logs/sesslog.log if you don\'t want auto rollover/rotation.',undef],
 ['pidfile','PID File',40,\&textinput,'pid','(\S*)',undef,
  'Blank to skip writing a pid file. *nix users need pid files.
   Leave it blank in Windows.<br /> You have to restart the service before you get a pid file in the new location.',undef],

[0,0,0,\&heading,'Logging'],
 ['silent','Silent Mode',0,\&checkbox,'','(.*)',undef,
  'Checked means don\'t print log messages to the console. AsADaemon overrides this.',undef],
 ['ConnectionLog','Connections Logging',0,\&checkbox,1,'(.*)',undef,
  'Log an event each time a new connection is received.',undef],
 ['SessionLimitLog','Session Limit Logging',0,\&checkbox,1,'(.*)',undef,
  'Log an event each time the above session limits are triggered.',undef],
 ['ClientValLog','Client Validation Logging',0,\&checkbox,'','(.*)',undef,
  'Enables verbose logging of client validation actions in the maillog.',undef],
 ['SenderValLog','Sender Validation Logging',0,\&checkbox,'','(.*)',undef,
  'Enables verbose logging of sender validation actions in the maillog.',undef],
 ['RecipientValLog','Recipient Validation Logging',0,\&checkbox,'','(.*)',undef,
  'Enables verbose logging of recipient validation actions in the maillog.',undef],
 ['DelayLog','Delaying Logging',0,\&checkbox,1,'(.*)',undef,
  'Enables verbose logging of all Delaying actions in the maillog.',undef],
 ['SPFLog','SPF Logging',0,\&checkbox,'','(.*)',undef,
  'Enables verbose logging of all SPF checks in the maillog.<br />
   Default is to log failures only.',undef],
 ['RBLLog','RBL Logging',0,\&checkbox,'','(.*)',undef,
  'Enables verbose logging of all RWL, RBL & URIBL checks in the maillog. Default is to log failures only.',undef],
 ['AvLog','AV Logging',0,\&checkbox,'','(.*)',undef,
  'Enables verbose logging of AV check failures in the maillog.',undef],
 ['RELog','RE Matches Logging',0,\&checkbox,'','(.*)',undef,
  'Enables logging of regular expressions (RE) matches in the maillog.',undef],
 ['IPMatchLog','IP Matches Logging',0,\&checkbox,'','(.*)',undef,
  'Enables logging of IP addresses matches in the maillog.',undef],
 ['RateLimitLog','RateLimit Logging',0,\&checkbox,'','(.*)',undef,
  'Enables logging of rate-limit actions in the maillog.',undef],
 ['EmailInterfaceLog','Email Interface Logging',0,\&checkbox,1,'(.*)',undef,
  'Enables verbose logging of all Email Interface actions in the maillog.',undef],
 ['AdminConnectionLog','Admin Connections Logging',0,\&checkbox,'','(.*)',undef,
  'Log an event each time a new web admin connection is received.<br />
   Default is to log authentication failures only.',undef],
 ['MaintenanceLog','Maintenance Logging',0,\&checkbox,1,'(.*)',undef,
  'Enables verbose logging of all maintenance actions (whitelist saving, delaying and rate-limit<br />
   databases cleaning, stats uploading, greylist freshening) in the maillog.',undef],
 ['ServerSessionLog','Server Side Session Logging',0,\&checkbox,'','(.*)',undef,
  'Enables logging of server-side smtp conversation in the session log.',undef],
 ['noLog','Don\'t Log these IP\'s*',60,\&textinput,'','(\S*)',\&configMakeIPRe,
  'Enter IP addresses that you don\'t want to be logged, separated by pipes (|).<br />
  This can be IP address of the SMTP service monitoring agent. For example: 127.0.0.1|10.',undef],
 ['LogRollDays','Roll the Logfile How Often?',5,\&textinput,14,'([\d\.]+)',undef,
  'ASSP closes and renames the log file after this number of days. Decimals are ok. For example: 14 or 0.5',undef],
 ['LogRotateCopies','Rotate the Logfile',5,\&textinput,0,'(\d+)',undef,
  'If set to 0, ASSP rolls the log files adding roll-over date to the file names and doesn\'t delete old logs.<br />
   If greater than 0, ASSP rotates the log files in this many copies adding numbers to the file names.<br />
   Set this to prevent log files directory from growing too large.',undef],

[0,0,0,\&heading,'Security'],
 ['runAsUser','Run as UID',20,\&textinput,'','(\S*)',undef,
  'The *nix user name to assume after startup: assp or nobody -- requires ASSP restart.',undef],
 ['runAsGroup','Run as GID',20,\&textinput,'','(\S*)',undef,
  'The *nix group to assume after startup: assp or nogroup -- requires ASSP restart.',undef],
 ['ChangeRoot','Change Root',40,\&textinput,'','(.*)',undef,
  'Non-blank means to run in chroot jail in *nix. You need an etc/protocols file to make this work<br />
   Copy or link the file to your new root directory -- requires ASSP restart.',undef],
 # I hate password input, but if you like it, uncomment this line and comment the next one. -- just quit bugging me about it!
 ['webAdminPassword','Web Admin Password',20,\&passwdinput,'nospam4me','(.{5,}|)',undef,
 #['webAdminPassword','Web Admin Password',20,\&textinput,'nospam4me','(.{5,}|)',undef,
  'This is your password for the administrative interface -- Must be at least 5 characters long.<br />
   No authorization is required when password is empty.',undef],
 ['allowAdminConnections','Allow Admin Connections*',60,\&textinput,'','(.*)',\&configMakeIPRe,
  'This is an optional list of IP addresses from which you will accept web admin connections, separated by pipes (|).<br />
   For example: 127.0.0.1|10. Blank means accept all connections. 127.0.0.1 means accept connections from the localhost.<br />
   Note that IP source addresses are very easy to spoof, so this should not be considered as a security feature.<br />
   <span class="negative">If you make a mistake here you will disable your web admin interface and have to manually edit your configuration file to fix it.</span>',undef],

[0,0,0,\&heading,'Other Settings'],
 ['MaxBytes','Max Bytes',10,\&textinput,20000,'(\d+)',undef,
  'How many bytes of the message will ASSP look at? For example: 20000',undef],
 ['MaxRebuildBytes','Max Rebuild Bytes',10,\&textinput,10000,'(\d+)',undef,
  'How many bytes of the message will ASSP look at during spam database rebuild?<br />
   For example: 10000',undef],
 ['KeepWhitelistedSpam','Keep Whitelisted Spam',0,\&checkbox,'','(.*)',undef,
  'Check this box if you don\'t want rebuildspamdb to remove entries from the spam collection
   after subsequent whitelisting.<br /> Checking this box will speed up your rebuild.',undef],
 ['RamSaver','Use less RAM to rebuild the spamdb',0,\&checkbox,'','(.*)',undef,
  'Checking this slows down your rebuildspamdb process, but will do so with less ram.',undef],
 ['IncomingBufSize','Size of TCP/IP Incoming Buffer',10,\&textinput,4096,'(\d+)',undef,
  'Set this to 65536 if you want to gain some speed at the cost of memory, 4096 is the default.<br />
   For example: 4096',undef],
 ['OutgoingBufSize','Size of TCP/IP Outgoing Buffer',10,\&textinput,102400,'(\d+)',undef,
  'If ASSP talks to the internet over a modem change this to 4096, 102400 is the default.<br />
   For example: 102400',undef],
 ['OrderedTieHashSize','Ordered-Tie hash table size',10,\&textinput,5000,'(\d+)',undef,
  'Tunable value of the size of the hash tables used by both ASSP and rebuildspamdb.pl (default = 5000).<br />
   Larger numbers mean more RAM, fewer disk hits. Adjust down to use less RAM.',undef],
 ['RestartEvery','Restart Every',10,\&textinput,0,'(\d+)',undef,
  'Program terminates after this many seconds, this is really only useful if ASSP runs as a service or in a script that restarts<br />
   it after it stops. Note: the current timeout must expire before the new setting is loaded.',undef],
 ['MaintenanceInterval','Maintenance Interval',10,\&textinput,3600,'(\d+)',undef,
  'How often (in seconds) to do maintenance actions: whitelist saving, Delaying &amp; Ratelimit databases cleaning.<br />
   Note: the current timeout must expire before the new setting is loaded, or you can restart.
   Defaults to 1 hour.',undef],
 ['totalizeSpamStats','Upload Consolidated Spam Statistics',0,\&checkbox,1,'(.*)',undef,
  'Checked means your ASSP will upload its totalled statistics to the <a href="http://assp.sourceforge.net/cgi-bin/total.pl" rel="external">ASSP web site totals</a>.<br />
   This is a great marketing tool for the ASSP project; please don\'t disable it unless you\'ve got
   a good reason to.<br /> No private information is being disclosed by this upload.',undef],
 ['noGreyListUpload','Don\'t Upload Greylist Stats',0,\&checkbox,'','(.*)',undef,
  'Check this to disable the greylist upload when rebuildspamdb runs.',undef],
 ['nogreydownload','Don\'t auto-download the greylist file',0,\&checkbox,'','(.*)',undef,
  'Set this checkbox if don\'t use the greylist or want to download it manually.',undef],
 ['EnableCorpusInterface','Enable Corpus Interface',0,\&checkbox,1,'(.*)',undef,
  'Enable corpus manipulation through Web Admin interface. Uncheck to save some memory &amp; CPU cycles.',undef],
 ['EnableHTTPCompression','Enable HTTP Compression for Web Admin interface',0,\&checkbox,1,'(.*)',undef,
  'Enable HTTP Compression for faster Web Admin interface loading.<br />
   This requires an installed <a href="http://search.cpan.org/dist/Compress-Zlib/" rel="external">Compress::Zlib</a> module in PERL.',undef],
 ['EnableFloatingMenu','Enable floating of Menu Panel',0,\&checkbox,1,'(.*)',undef,
  'Enable floating of menu panel for Web Admin interface. Floating Div code taken from <a href="http://www.javascript-fx.com" rel="external">www.javascript-fx.com</a> site.',undef],
 ['MaillogTailBytes','Maillog Tail Bytes',10,\&textinput,10000,'(\d+)',undef,
  'How many bytes of the maillog will be shown in a tail window? Default: 10000.',undef],
 ['MaillogTailWrapColumn','Maillog Tail Wrap Column',5,\&textinput,80,'(\d+)',undef,
  'Wrap the maillog tail window text at a specific column. Enter 0 for no wrapping.',undef],
 ['MaillogContextLines','Maillog Context Lines',5,\&textinput,12,'(\d+)',undef,
  'Display this many context lines when searching in maillogs.',undef],
 ['UseLocalTime','Use Local Time',0,\&checkbox,1,'(.*)',undef,
  'Use local time and timezone offset rather than UTC time in the mail headers.',undef],
 ['BackupCopies','Backup Copies',1,\&textinput,3,'(\d+)',undef,
  'Keep this many backup copies of important files.',undef],
 ['webAdminCharset','Web Admin Charset',20,\&textinput,'utf-8','(\S*)',undef,
  'The character set used for the administrative interface.',undef],
 ['DetailedStats','Detailed Statistics',0,\&checkbox,'','(.*)',undef,
  'Enable displaying of (Protocol / Data) contribution and (Min - Max) latency in Statistics.',undef],
 ['ShowTooltipsIP','Display Tooltips On IP\'s',0,\&checkbox,1,'(.*)',\&configUpdateShowTooltipsIP,
  'Display Tooltips with rDNS information on IP addresses.<br />
   This requires an installed <a href="http://search.cpan.org/dist/Net-DNS/" rel="external">Net::DNS</a> module in PERL.',undef],
 ['ShowTooltipsHost','Display Tooltips On Host Names',0,\&checkbox,1,'(.*)',undef,
  'Display Tooltips with DNS information also on Host Names.',undef],
 ['ShowTooltipsEmail','Display Tooltips On Email addresses',0,\&checkbox,'','(.*)',undef,
  'Display Tooltips on Email addresses.',undef],
 ['ShowNews','Highlight New Settings',0,\&checkbox,1,'(.*)',undef,
  'Highlight new settings in web admin interface.',undef]);

sub configLoad {
 # load configuration file
 print "loading config -- base='$base'\n";
 open(F,"<$base/assp.cfg");
 local $/;
 (%Config)=split(/:=|\n/,<F>);
 close F;
}

sub configInit {
 # check config version
 if ((my $cmp=vercmp($Config{ConfigVersion},"$version$modversion"))>0) {
  my $msg="config file version is too new ($Config{ConfigVersion}), exiting";
  mlog(0,$msg);
  die ucfirst($msg);
 } elsif ($cmp<0) {
  my $msg="config file version is too old ($Config{ConfigVersion}), run upgrade.pl";
  mlog(0,$msg);
  die ucfirst($msg);
 }
 # set nonexistent settings to default values
 foreach my $c (@Config) {
  if ($c->[0] && !(exists $Config{$c->[0]})) {
   $Config{$c->[0]}=$c->[4];
  }
 }
 $Config{base}=$base;
 # -- this sets the variable name with the same name as the config key to the new value
 # -- for example $Config{myName}='ASSP-nospam' -> $myName='ASSP-nospam';
 while (my ($c,$v)=each(%Config)) {
  ${$c}=$v;
 }
}

sub configInitRE {
 # turn settings into regular expressions
 @PossibleOptionFiles=();
 foreach my $c (@Config) {
  if ($c->[6]==\&configMakeRe ||
      $c->[6]==\&configMakeSLRe ||
      $c->[6]==\&configMakeIPRe ||
      $c->[6]==\&configMakeSLIPRe ||
      $c->[6]==\&configCompileRe ||
      $c->[6]==\&configUpdateRBLSP ||
      $c->[6]==\&configUpdateRWLSP ||
      $c->[6]==\&configUpdateURIBLSP) {
   $c->[6]->($c->[0],'',${$c->[0]},'Initializing',$c->[1]);
   push(@PossibleOptionFiles,[$c->[0],$c->[1],$c->[6]]);
  } elsif ($c->[6]==\&configMakeSubTagRe) {
   # turn subject prepends into regular expressions
   $c->[6]->($c->[0],'',${$c->[0]},'Initializing',$c->[1]);
  }
 }
}

sub configInitUpdate {
 configUpdateBadAttachL1('BadAttachL1','',$Config{BadAttachL1},'Initializing');
 configUpdateRWL('ValidateRWL','',$Config{ValidateRWL},'Initializing');
 configUpdateRBL('ValidateRBL','',$Config{ValidateRBL},'Initializing');
 configUpdateURIBL('ValidateURIBL','',$Config{ValidateURIBL},'Initializing');
 configUpdateSRS('EnableSRS','',$Config{EnableSRS},'Initializing');
 foreach my $k (sort keys %Config) {
  configUpdateRLIBT($k,'',$Config{$k},'Initializing') if $k=~/^RLIBT.*$/;
 }
 configUpdateShowTooltipsIP('ShowTooltipsIP','',$Config{ShowTooltipsIP},'Initializing');
 configUpdateLog2('freqSpam','',$Config{freqSpam},'Initializing');
 configUpdateLDAPHost('LDAPHost','',$Config{LDAPHost},'Initializing');
}

sub configSave {
 my $fil="$base/assp.cfg";
 backupFile($fil);
 open(F,">$fil");
 foreach (sort keys %Config) {print F "$_:=$Config{$_}\n";}
 close F;
}

sub optionFilesReload {
 # check if options files have been updated and need to be re-read
 foreach my $f (@PossibleOptionFiles) {
  $f->[2]->($f->[0],$Config{$f->[0]},$Config{$f->[0]},'',$f->[1]) if $Config{$f->[0]}=~/^ *file: *(.+)/i && fileUpdated($1);
 }
}

sub configMakeRe {
 my ($name, $old, $new, $init)=@_;
 mlog(0,"admin update: $name changed from '$old' to '$new'") unless $init || $new eq $old;
 $new=checkOptionList($new,$name,$init);
 $new=~s/([\.\[\]\-\(\)\*\+\\])/\\$1/g;
 $new||='^(?!)'; # regexp that never matches
 $MakeRE{$name}->($new);
 '';
}

sub configCompileRe {
 my ($name, $old, $new, $init)=@_;
 mlog(0,"admin update: $name changed from '$old' to '$new'") unless $init || $new eq $old;
 $new=checkOptionList($new,$name,$init);
 $new||='^(?!)'; # regexp that never matches
 # trim long matches to 32 chars including '...' at the end
 SetRE($name.'RE',"($new)(?{length(\$1)>32?substr(\$1,0,32-3).'...':\$1})",'is',$name);
 '';
}

# this checks and corrects a | separated list 
# and handles the options in a file
sub checkOptionList {
 my ($value,$name,$init)=@_;
 my $fromfile=0;
 if ($value=~/^ *file: *(.+)/i) {
  # the option list is actually saved in a file.
  $fromfile=1;
  my $fil=$1; $fil="$base/$fil" if $fil!~/^\Q$base\E/i;
  local $/;
  my @s=stat($fil);
  my $mtime=$s[9];
  $FileUpdate{$fil}=$mtime;
  if (open(OL,"<$fil")) {
   $value=<OL>;
   # clean off comments
   $value=~s/#.*//g;
   # replace newlines (and the whitespace that surrounds them) with a |
   $value=~s/\s*\n\s*/|/g;
   close OL;
   mlog(0,"option list file '$fil' reloaded ($name)") unless $init;
  } else {
   mlog(0,"failed to open option list file '$fil' ($name): $!");
   $value='';
  }
 }
 $value=~s/\|\|+/\|/g;
 $value=~s/^\s*\|?//;
 $value=~s/\|?\s*$//;
 # set corrected value back in Config
 ${$name}=$Config{$name}=$value unless $fromfile;
 return $value;
}

# make tagged prepended subject RE
sub configMakeSubTagRe {
 my ($name, $old, $new, $init)=@_;
 mlog(0,"admin update: $name changed from '$old' to '$new'") unless $init || $new eq $old;
 ${$name}=$new;
 $new=join '\S+', map{quotemeta($_)} split('TAG',$new);
 $new||='^(?!)'; # regexp that never matches
 SetRE($name.'TagRE',$new,'',$name);
 '';
}

# make spamlover RE
sub configMakeSLRe {
 my ($name, $old, $new, $init, $desc, $checked)=@_;
 mlog(0,"admin update: $name changed from '$old' to '$new'") unless $init || $new eq $old;
 $new=checkOptionList($new,$name,$init) unless $checked;
 my (@uad,@u,@d);
 foreach my $a (split(/\|/,$new)) {
  if ($a=~/\S\@\S/) {
   push(@uad,$a);
  } elsif ($a=~/^\@/) {
   push(@d,$a);
  } else {
   push(@u,$a);
  }
 }
 my @s;
 push(@s,'^('.join('|',@uad).')$') if @uad;
 push(@s,'^('.join('|',@u).')@') if @u;
 push(@s,'('.join('|',@d).')$') if @d;
 my $s=join('|',@s);
 $s||='^(?!)'; # regexp that never matches
 SetRE($MakeSLRE{$name},$s,'i',$desc);
 '';
}

# make IP address RE
# allow for CIDR notation if Net::IP::Match::Regexp available
sub configMakeIPRe {
 my ($name, $old, $new, $init, $desc, $checked)=@_;
 mlog(0,"admin update: $name changed from '$old' to '$new'") unless $init || $new eq $old;
 $new=checkOptionList($new,$name,$init) unless $checked;
 if ($CanMatchCIDR) {
  my %ips;
  foreach my $l (split(/\|/,$new)) {
   if (my @matches=$l=~/^($IPQuadRE)\.?(\/\d{1,2})?\s*(.*)\s*$/io) {
    my $ip=shift @matches;
    my $desc=pop @matches;
    my $bits=pop @matches;
    my $dcnt=($ip=~tr/\.//);
    if ($dcnt>=3) {
     $bits||='/32';
    } elsif ($dcnt>=2) {
     $ip.='.0';
     $bits||='/24';
    } elsif ($dcnt>=1) {
     $ip.='.0'x2;
     $bits||='/16';
    } else {
     $ip.='.0'x3;
     $bits||='/8';
    }
    $desc=~s/'/\\'/g;
    $desc||=1;
    $ips{"$ip$bits"}=$desc;
   }
  }
  if (scalar keys %ips) {
   $new=Net::IP::Match::Regexp::create_iprange_regexp(\%ips);
  } else {
   $new=qr/^(?!)/; # regexp that never matches
  }
  ${$MakeIPRE{$name}}=$new;
 } else {
  my %ips;
  foreach my $l (split(/\|/,$new)) {
   if (my @matches=$l=~/^($IPQuadRE)\.?(\/\d{1,2})?\s*(.*)\s*$/io) {
    my $ip=shift @matches;
    my $desc=pop @matches;
    my $bits=pop @matches; # ignore bits
    $desc=~s/'/\\'/g;
    $desc||=1;
    $ips{$ip}=$desc;
   }
  }
  my @ips;
  while (my ($ip,$desc)=each(%ips)) {
   $ip=~s/([\.\[\]\-\(\)\*\+\\])/\\$1/g;
   $ip||='^(?!)'; # regexp that never matches
   $desc=~s/'/\\'/g;
   $desc||=1;
   push(@ips,"$ip(?{'$desc'})");
  }
  $new=join('|',@ips);
  use re 'eval';
  eval{${$MakeIPRE{$name}}=qr/^($new)/};
  mlog(0,"regular expression error in '$r' for $desc: $@") if $@;
 }
 '';
}

# make mixed (email address/IP address) RE
sub configMakeSLIPRe {
 my ($name, $old, $new, $init, $desc)=@_;
 mlog(0,"admin update: $name changed from '$old' to '$new'") unless $init || $new eq $old;
 $new=checkOptionList($new,$name,$init);
 my (@a,@ip);
 foreach my $l (split(/\|/,$new)) {
  if ($l=~/^($IPQuadRE)\.?(\/\d{1,2})?\s*(.*)\s*$/io) {
   push(@ip,$l);
  } else {
   push(@a,$l);
  }
 }
 my $s=join('|',@a);
 configMakeSLRe($name,'',$s,'Cascading','',1);
 $s=join('|',@ip);
 configMakeIPRe($name,'',$s,'Cascading',$desc,1);
}

sub SetRE {
 my ($var,$r,$f,$desc)=@_;
 use re 'eval';
 eval{$$var=qr/(?$f)$r/};
 mlog(0,"regular expression error in '$r' for $desc: $@") if $@;
}

# compile the regular expression for the local domains
sub setLDRE {
 my $new=shift;
 $new||='^(?!)'; # regexp that never matches
 SetRE(LDRE,"^($new)\$",'i','Local Domains');
}

# compile the regular expression for the local host names
sub setLHNRE {
 my @h;
 foreach my $h (split(/\|/,$_[0])) {
  push(@h,$h);
 }
 my @s;
 push(@s,'localhost'); # 'localhost' alias
 push(@s,'127.0.0.1'); # loopback interface address
 push(@s,join('|',@h)) if @h;
 my $s=join('|',@s);
 $s||='^(?!)'; # regexp that never matches
 SetRE(LHNRE,"^($s)\$",'i','Local Host Names');
}

# compile the regular expression for the bounce senders addresses
sub setBSRE {
 my (@uad,@u,@d);
 foreach my $a (split(/\|/,$_[0])) {
  if ($a=~/\S\@\S/) {
   push(@uad,$a);
  } elsif ($a=~/^\@/) {
   push(@d,$a);
  } else {
   push(@u,$a);
  }
 }
 my @s;
 push(@s,'^\s*$'); # null sender address
 push(@s,'^('.join('|',@uad).')$') if @uad;
 push(@s,'^('.join('|',@u).')@') if @u;
 push(@s,'('.join('|',@d).')$') if @d;
 my $s=join('|',@s);
 $s||='^(?!)'; # regexp that never matches
 SetRE(BSRE,$s,'i','Bounce Senders');
}

# compile the blacklisted domains regular expression
sub setBLDRE {
 my $new=shift;
 $new||='^(?!)'; # regexp that never matches
 SetRE(BLDRE1,"($new)\$",'i','Blacklisted Domains');
 SetRE(BLDRE2,"($new) ",'i','Blacklisted Domains');
}

sub setWLDRE {
 my $new=shift;
 $new||='^(?!)'; # regexp that never matches
 SetRE(WLDRE,"($new)\$",'i','Whitelisted Domains');
}

# compile the regular expression for the list of country code TLDs
sub setURIBLCCTLDSRE {
 my @doms;
 foreach my $d (split(/\|/,$_[0])) {
  push(@doms,"[^\\.]+\\.$d");
 }
 my $s=join('|',@doms);
 $s||='^(?!)'; # regexp that never matches
 SetRE(URIBLCCTLDSRE,"($s)\$",'i','Country Code TLDs');
}

# compile the URIBL whitelist regular expression
sub setURIBLWLDRE {
 my $new=shift;
 $new||='^(?!)'; # regexp that never matches
 SetRE(URIBLWLDRE,"^($new)\$",'i','Whitelisted URIBL Domains');
}

sub configChangeMailPort {
 my ($name, $old, $new)=@_;
 if ($>==0 || $new>=1024) {
  # change the listenport
  $listenPort=$new;
  $Lsn->close() if $Lsn;
  if ($Lsn=newListen($listenPort)) {
   mlog(0,"listening on new mail port $listenPort (changed from $old) per admin request");
   newTask(taskNewSMTPConnection($Lsn),'NORM',0,'S');
  }
  return '';
 } else {
  # don't have permissions to change
  mlog(0,"request to listen on new mail port $listenPort (changed from $old) -- restart required; euid=$>");
  return "<br />Restart required; euid=$>";
 }
}

sub configChangeMailPort2 {
 my ($name, $old, $new)=@_;
 if ($>==0 || $new>=1024) {
  # change the listenport2
  $listenPort2=$new;
  $Lsn2->close() if $Lsn2;
  if ($Lsn2=newListen($listenPort2)) {
   mlog(0,"listening on new secondary mail port $listenPort2 (changed from $old) per admin request");
   newTask(taskNewSMTPConnection($Lsn2),'NORM',0,'S');
  }
  return '';
 } else {
  # don't have permissions to change
  mlog(0,"request to listen on new secondary mail port $listenPort2 (changed from $old) -- restart required; euid=$>");
  return "<br />Restart required; euid=$>";
 }
}

sub configChangeAdminPort {
 my ($name, $old, $new)=@_;
 if ($>==0 || $new>=1024) {
  # change the listenport
  $webAdminPort=$new;
  $WebSocket->close();
  if ($WebSocket=newListen($webAdminPort)) {
   mlog(0,"listening on new admin port $new (changed from $old) per admin request");
   newTask(taskNewWebConnection($WebSocket),'NORM',0,'W');
  } else {
   # couldn't open the port -- switch back
   $webAdminPort=$old;
   if ($WebSocket=newListen($webAdminPort)) {
    mlog(0,"couldn't open new port -- still listening on $old");
    newTask(taskNewWebConnection($WebSocket),'NORM',0,'W');
    $Config{$name}=$old;
    return "<span class=\"negative\">Couldn't open new port $new</span>";
   } else {
    # should not happen
   }
  }
  return '';
 } else {
  # don't have permissions to change
  mlog(0,"request to listen on new admin port $new (changed from $old) -- restart required; euid=$>");
  return "<br />Restart required; euid=$>";
 }
}

sub configChangeRelayPort {
 my ($name, $old, $new)=@_;
 unless ($relayHost && $new) {
  if ($Relay) {
   $Relay->close();
   mlog(0,'relay port disabled');
   return '<br />relay port disabled';
  } else {
   return "<br />relayHost ($relayHost) and relayPort ($new) must be defined to enable relaying";
  }
 }
 if ($>==0 || $new>=1024) {
  # change the listenport
  $relayPort=$new;
  $Relay->close() if $Relay;
  if ($Relay=newListen($relayPort)) {
   mlog(0,"listening for relay connections at $relayPort -- changed per admin request");
   newTask(taskNewSMTPConnection($Relay),'NORM',0,'S');
  }
  return '';
 } else {
  # don't have permissions to change
  mlog(0,"request to listen on new relay port $new (changed from $old) -- restart required; euid=$>");
  return "<br />Restart required; euid=$>";
 }
}

sub configChangeLogfile {
 my ($name, $old, $new)=@_;
 close LOG if $logfile;
 $logfile=$new;
 if ($logfile && open(LOG,">>$base/$logfile")) {
  my $oldfh=select(LOG); $|=1; select($oldfh);
 }
 mlog(0,"log file changed to '$new' from '$old' per admin request");
 '';
}

sub configChangeSlogfile {
 my ($name, $old, $new)=@_;
 close SLOG if $slogfile;
 $slogfile=$new;
 if ($slogfile && open(SLOG,">>$base/$slogfile")) {
  my $oldfh=select(SLOG); $|=1; select($oldfh);
 }
 mlog(0,"sessions log file changed to '$new' from '$old' per admin request");
 '';
}

# Bad Attachment Settings, Checks and Update.
sub configUpdateBadAttachL1 {
 my ($name, $old, $new, $init)=@_;
 mlog(0,"Badattach Level 1 updated from '$old' to '$new'") unless $init;
 $new||='^(?!)'; # regexp that never matches
 SetRE(badattachL1RE,qq[(".*\\.(?:$new)"|.*\\.(?:$new)\\s)],'i','Bad Attachment L1');
 configUpdateBadAttachL2('BadAttachL2','',$Config{BadAttachL2},$new);
}

sub configUpdateBadAttachL2 {
 my ($name, $old, $new, $init)=@_;
 mlog(0,"Badattach Level 2 updated from '$old' to '$new'") unless $init;
 $new.='|'.$init;
 SetRE(badattachL2RE,qq[(".*\\.(?:$new)"|.*\\.(?:$new)\\s)],'i','Bad Attachment L2');
 configUpdateBadAttachL3('BadAttachL3','',$Config{BadAttachL3},$new);
}

sub configUpdateBadAttachL3 {
 my ($name, $old, $new, $init)=@_;
 mlog(0,"Badattach Level 3 updated from '$old' to '$new'") unless $init;
 $new.='|'.$init;
 SetRE(badattachL3RE,qq[(".*\\.(?:$new)"|.*\\.(?:$new)\\s)],'i','Bad Attachment L2');
 $badattachRE[1]=$badattachL1RE;
 $badattachRE[2]=$badattachL2RE;
 $badattachRE[3]=$badattachL3RE;
 '';
}

# SenderMX Settings Checks, and Update.
sub configUpdateSenderMX {
 my ($name, $old, $new, $init)=@_;
 mlog(0,"SenderMX updated from '$old' to '$new'") unless $init;
 $SenderMX=$Config{SenderMX}=$new;
 unless ($CanUseDNS) {
  mlog(0,"SenderMX updated from '1' to ''") if $Config{SenderMX};
  ($SenderMX,$Config{SenderMX})=();
  return '<span class="negative">*** Net::DNS must be installed before enabling SenderMX.</span>';
 }
}

# LDAP Hosts Settings.
sub configUpdateLDAPHost {
 my ($name, $old, $new, $init)=@_;
 mlog(0,"LDAP Hosts updated from '$old' to '$new'") unless $init || $new eq $old;
 $LDAPHost=$new;
 $new=checkOptionList($new,'LDAPHost',$init);
 @ldaplist=split(/\|/,$new);
}

# RWL Settings Checks, and Update.
sub configUpdateRWL {
 my ($name, $old, $new, $init)=@_;
 mlog(0,"RWL-Enable updated from '$old' to '$new'") unless $init;
 $ValidateRWL=$Config{ValidateRWL}=$new;
 unless ($CanUseRWL) {
  mlog(0,"RWL-Enable updated from '1' to ''") if $Config{ValidateRWL};
  ($ValidateRWL,$Config{ValidateRWL})=();
  return '<span class="negative">*** Net::DNS must be installed before enabling RWL.</span>';
 } else {
  configUpdateRWLMH('RWLminhits','',$Config{RWLminhits},'Cascading');
 }
}

sub configUpdateRWLMH {
 my ($name, $old, $new, $init)=@_;
 mlog(0,"RWL Minimum Hits updated from '$old' to '$new'") unless $init;
 $RWLminhits=$new;
 if ($new<=0) {
  mlog(0,"RWL-Enable updated from '1' to ''") if $Config{ValidateRWL};
  ($ValidateRWL,$Config{ValidateRWL})=();
  return '<span class="negative">*** RWLminhits must be defined and positive before enabling RWL.</span>';
 } else {
  configUpdateRWLMR('RWLmaxreplies','',$Config{RWLmaxreplies},'Cascading');
 }
}

sub configUpdateRWLMR {
 my ($name, $old, $new, $init)=@_;
 mlog(0,"RWL Maximum Replies updated from '$old' to '$new'") unless $init;
 $RWLmaxreplies=$new;
 if ($new<$RWLminhits) {
  mlog(0,"RWL-Enable updated from '1' to ''") if $Config{ValidateRWL};
  ($ValidateRWL,$Config{ValidateRWL})=();
  return '<span class="negative">*** RWLmaxreplies must be more than or equal to RWLminhits before enabling RWL.</span>';
 } else {
  configUpdateRWLSP('RWLServiceProvider','',$Config{RWLServiceProvider},'Cascading');
 }
}

sub configUpdateRWLSP {
 my ($name, $old, $new, $init)=@_;
 mlog(0,"RWL Service Providers updated from '$old' to '$new'") unless $init || $new eq $old;
 $RWLServiceProvider=$new;
 $new=checkOptionList($new,'RWLServiceProvider',$init);
 my $domains=($new=~s/\|/|/g)+1;
 if ($domains<$RWLmaxreplies) {
  mlog(0,"RWL-Enable updated from '1' to ''") if $Config{ValidateRWL};
  ($ValidateRWL,$Config{ValidateRWL})=();
  return '<span class="negative">*** RWLServiceProvider must contain more than or equal to RWLmaxreplies domains before enabling RWL.</span>';
 } elsif ($CanUseRWL) {
  my $res=Net::DNS::Resolver->new;
  @nameservers=$res->nameservers;
  @rwllist=split(/\|/,$new);
  if ($init && $ValidateRWL) {
   return ' & RWL activated';
  } else {
   return '';
  }
 }
}

# RBL Settings Checks, and Update.
sub configUpdateRBL {
 my ($name, $old, $new, $init)=@_;
 mlog(0,"RBL-Enable updated from '$old' to '$new'") unless $init;
 $ValidateRBL=$Config{ValidateRBL}=$new;
 unless ($CanUseRBL) {
  mlog(0,"RBL-Enable updated from '1' to ''") if $Config{ValidateRBL};
  ($ValidateRBL,$Config{ValidateRBL})=();
  return '<span class="negative">*** Net::DNS must be installed before enabling RBL.</span>';
 } else {
  configUpdateRBLMH('RBLmaxhits','',$Config{RBLmaxhits},'Cascading');
 }
}

sub configUpdateRBLMH {
 my ($name, $old, $new, $init)=@_;
 mlog(0,"RBL Maximum Hits updated from '$old' to '$new'") unless $init;
 $RBLmaxhits=$new;
 if ($new<=0) {
  mlog(0,"RBL-Enable updated from '1' to ''") if $Config{ValidateRBL};
  ($ValidateRBL,$Config{ValidateRBL})=();
  return '<span class="negative">*** RBLmaxhits must be defined and positive before enabling RBL.</span>';
 } else {
  configUpdateRBLMR('RBLmaxreplies','',$Config{RBLmaxreplies},'Cascading');
 }
}

sub configUpdateRBLMR {
 my ($name, $old, $new, $init)=@_;
 mlog(0,"RBL Maximum Replies updated from '$old' to '$new'") unless $init;
 $RBLmaxreplies=$new;
 if ($new<$RBLmaxhits) {
  mlog(0,"RBL-Enable updated from '1' to ''") if $Config{ValidateRBL};
  ($ValidateRBL,$Config{ValidateRBL})=();
  return '<span class="negative">*** RBLmaxreplies must be more than or equal to RBLmaxhits before enabling RBL.</span>';
 } else {
  configUpdateRBLSP('RBLServiceProvider','',$Config{RBLServiceProvider},'Cascading');
 }
}

sub configUpdateRBLSP {
 my ($name, $old, $new, $init)=@_;
 mlog(0,"RBL Service Providers updated from '$old' to '$new'") unless $init || $new eq $old;
 $RBLServiceProvider=$new;
 $new=checkOptionList($new,'RBLServiceProvider',$init);
 my $domains=($new=~s/\|/|/g)+1;
 if ($domains<$RBLmaxreplies) {
  mlog(0,"RBL-Enable updated from '1' to ''") if $Config{ValidateRBL};
  ($ValidateRBL,$Config{ValidateRBL})=();
  return '<span class="negative">*** RBLServiceProvider must contain more than or equal to RBLmaxreplies domains before enabling RBL.</span>';
 } elsif ($CanUseRBL) {
  my $res=Net::DNS::Resolver->new;
  @nameservers=$res->nameservers;
  @rbllist=split(/\|/,$new);
  if ($init && $ValidateRBL) {
   return ' & RBL activated';
  } else {
   return '';
  }
 }
}

# URIBL Settings Checks, and Update.
sub configUpdateURIBL {
 my ($name, $old, $new, $init)=@_;
 mlog(0,"URIBL-Enable updated from '$old' to '$new'") unless $init;
 $ValidateURIBL=$Config{ValidateURIBL}=$new;
 unless ($CanUseURIBL) {
  mlog(0,"URIBL-Enable updated from '1' to ''") if $Config{ValidateURIBL};
  ($ValidateURIBL,$Config{ValidateURIBL})=();
  return '<span class="negative">*** Net::DNS must be installed before enabling URIBL.</span>';
 } else {
  configUpdateURIBLMH('URIBLmaxhits','',$Config{URIBLmaxhits},'Cascading');
 }
}

sub configUpdateURIBLMH {
 my ($name, $old, $new, $init)=@_;
 mlog(0,"URIBL Maximum Hits updated from '$old' to '$new'") unless $init;
 $URIBLmaxhits=$new;
 if ($new<=0) {
  mlog(0,"URIBL-Enable updated from '1' to ''") if $Config{ValidateURIBL};
  ($ValidateURIBL,$Config{ValidateURIBL})=();
  return '<span class="negative">*** URIBLmaxhits must be defined and positive before enabling URIBL.</span>';
 } else {
  configUpdateURIBLMR('URIBLmaxreplies','',$Config{URIBLmaxreplies},'Cascading');
 }
}

sub configUpdateURIBLMR {
 my ($name, $old, $new, $init)=@_;
 mlog(0,"URIBL Maximum Replies updated from '$old' to '$new'") unless $init;
 $URIBLmaxreplies=$new;
 if ($new<$URIBLmaxhits) {
  mlog(0,"URIBL-Enable updated from '1' to ''") if $Config{ValidateURIBL};
  ($ValidateURIBL,$Config{ValidateURIBL})=();
  return '<span class="negative">*** URIBLmaxreplies must be more than or equal to URIBLmaxhits before enabling URIBL.</span>';
 } else {
  configUpdateURIBLSP('URIBLServiceProvider','',$Config{URIBLServiceProvider},'Cascading');
 }
}

sub configUpdateURIBLSP {
 my ($name, $old, $new, $init)=@_;
 mlog(0,"URIBL Service Providers updated from '$old' to '$new'") unless $init || $new eq $old;
 $URIBLServiceProvider=$new;
 $new=checkOptionList($new,'URIBLServiceProvider',$init);
 my $domains=($new=~s/\|/|/g)+1;
 if ($domains<$URIBLmaxreplies) {
  mlog(0,"URIBL-Enable updated from '1' to ''") if $Config{ValidateURIBL};
  ($ValidateURIBL,$Config{ValidateURIBL})=();
  return '<span class="negative">*** URIBLServiceProvider must contain more than or equal to URIBLmaxreplies domains before enabling URIBL.</span>';
 } elsif ($CanUseURIBL) {
  my $res=Net::DNS::Resolver->new;
  @nameservers=$res->nameservers;
  @uribllist=split(/\|/,$new);
  if ($init && $ValidateURIBL) {
   return ' & URIBL activated';
  } else {
   return '';
  }
 }
}

# SRS Settings Checks, and Update.
sub configUpdateSRS {
 my ($name, $old, $new, $init)=@_;
 mlog(0,"SRS-Enable updated from '$old' to '$new'") unless $init;
 $EnableSRS=$Config{EnableSRS}=$new;
 unless ($CanUseSRS) {
  mlog(0,"SRS-Enable updated from '1' to ''") if $Config{EnableSRS};
  ($EnableSRS,$Config{EnableSRS})=();
  return '<span class="negative">*** Mail::SRS must be installed before enabling SRS.</span>';
 } else {
  configUpdateSRSAD('SRSAliasDomain','',$Config{SRSAliasDomain},'Cascading');
 }
}

sub configUpdateSRSAD {
 my ($name, $old, $new, $init)=@_;
 mlog(0,"SRS Alias Domain updated from '$old' to '$new'") unless $init;
 $SRSAliasDomain=$new;
 if ($new eq '') {
  mlog(0,"SRS-Enable updated from '1' to ''") if $Config{EnableSRS};
  ($EnableSRS,$Config{EnableSRS})=();
  return '<span class="negative">*** SRSAliasDomain must be defined before enabling SRS.</span>';
 } else {
  configUpdateSRSSK('SRSSecretKey','',$Config{SRSSecretKey},'Cascading');
 }
}

sub configUpdateSRSSK {
 my ($name, $old, $new, $init)=@_;
 mlog(0,"SRS Secret Key updated from '*****' to '*****'") unless $init;
 $SRSSecretKey=$new;
 if (length($new)<5) {
  mlog(0,"SRS-Enable updated from '1' to ''") if $Config{EnableSRS};
  ($EnableSRS,$Config{EnableSRS})=();
  return '<span class="negative">*** SRSSecretKey must be at least 5 characters long before enabling SRS.</span>';
 } elsif ($CanUseSRS) {
  if ($init && $EnableSRS) {
   return ' & SRS activated';
  } else {
   return '';
  }
 }
}

# RateLimit Settings Update.
sub configUpdateRLIBT {
 my ($name, $old, $new, $init)=@_;
 mlog(0,"$name updated from '$old' to '$new'") unless $init;
 ($name)=$name=~/^RLIBT(.*)$/;
 my ($limit,$interval,$block)=split('/',$new);
 $interval=unformatTimeInterval($interval,'m');
 $block=unformatTimeInterval($block,'m');
 # fill global %ConfigRateLimitEvents hash
 unless (exists $ConfigRateLimitEvents{$name}) {
  my $id=(keys %ConfigRateLimitEvents)>>1;
  $ConfigRateLimitEvents{$name}->{id}=$id;
  $ConfigRateLimitEvents{$name}->{name}=$name;
  $ConfigRateLimitEvents{$id}=$ConfigRateLimitEvents{$name};
 }
 my $event=$ConfigRateLimitEvents{$name};
 $event->{limit}=$limit;
 $event->{interval}=$interval;
 $event->{block}=$block;
 return '';
}

# Tooltips Settings Checks, and Update.
sub configUpdateShowTooltipsIP {
 my ($name, $old, $new, $init)=@_;
 mlog(0,"ShowTooltipsIP updated from '$old' to '$new'") unless $init;
 $ShowTooltipsIP=$Config{ShowTooltipsIP}=$new;
 unless ($CanUseDNS) {
  mlog(0,"ShowTooltipsIP updated from '1' to ''") if $Config{ShowTooltipsIP};
  ($ShowTooltipsIP,$Config{ShowTooltipsIP})=();
  return '<span class="negative">*** Net::DNS must be installed before enabling IP Tooltips.</span>';
 }
}

# Database File Logging Frequency Setup.
sub configUpdateLog2 {
 my ($name, $old, $new, $init)=@_;
 mlog(0,"Non Spam Logging Frequency updated from '$old' to '$new'") unless $init;
 $logFreq[1]=$logFreq[2]=$logFreq[3]=$logFreq[4]=$new;
 configUpdateLog3('freqNonSpam','',$Config{freqNonSpam},$new);
}

sub configUpdateLog3 {
 my ($name, $old, $new, $init)=@_;
 mlog(0,"Spam Logging Frequency updated from '$old' to '$new'") unless $init;
 $logFreq[5]=$logFreq[6]=$logFreq[7]=$logFreq[8]=$logFreq[9]=$new;
 return '';
}

1;