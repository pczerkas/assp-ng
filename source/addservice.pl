use Win32::Daemon;
use Win32::Service;

if(lc $ARGV[0] eq 'u') {
 Win32::Service::StopService('','ASSPSMTP') && sleep(1);
 Win32::Daemon::DeleteService('','ASSPSMTP') ||
   print STDERR "Failed to remove ASSP service: " . Win32::FormatMessage( Win32::Daemon::GetLastError() ) . "\n";
} elsif( lc $ARGV[0] eq 's') {
 if($s=Win32::Service::StartService('','ASSPSMTP')) {
   print "ASSP Service started ($s)\n";
 } else {
   print "Could not start ASSP service\n";
 }
} elsif( lc $ARGV[0] eq 'i') {
 unless($p=$ARGV[1]) {
  $p=$0;
  $p=~s/\w+\.pl/assp.pl/;
 }
 if($p2=$ARGV[2]) {
  $p2=~s/[\\\/]$//;
 } else {
  $p2=$p; $p2=~s/[\\\/]assp\.pl//i;
 }
 %Hash = (
    name    =>  'ASSPSMTP',
    display =>  'Anti-Spam Smtp Proxy',
    path    =>  "\"$^X\"",
    user    =>  '',
    pwd     =>  '',
    parameters => "\"$p\" \"$p2\"",
 );
 if( Win32::Daemon::CreateService( \%Hash ) ) {
    print "ASSP service successfully added.\n";
 } else {
    print "Failed to add ASSP service: " . Win32::FormatMessage( Win32::Daemon::GetLastError() ) . "\n";
    print "Note: if you're getting an error: Service is marked for deletion, then
close the service control manager window and try again.\n";
 }
} else {
print
"Usage:
  perl addservice.pl -i c:\\assp\\assp.pl   installs at location specified
                                          (base is assumed to be c:\\assp)
  perl addservice.pl -i c:\\assp\\assp.pl c:\\assp  -- installs the program and base
  perl addservice.pl -s                   starts the ASSP service
  perl addservice.pl -u                   uninstalls the ASSP service

Note that you must start the service after you install it, and that you must
stop it before you uninstall it. You can do this from the service control
manager.
";

}

