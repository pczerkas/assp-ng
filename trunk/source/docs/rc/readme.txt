Written for RedHat 7.x , and many others I believe would work with
minor mods, if any.

The script 'assp' should be copied into /etc/init.d/   and then
linked to the appropriate run-level directories for starting up
and shutting down..   For example, I run at init 3 at startup, so
my script is linked to /etc/rc3.d/S79assp  (just before
S80sendmail)  and also to /etc/rc0.d/K31assp  (just after sendmail
shutdown).  The scripts 'start' and 'stop' should be in the 'sane'
directory (ie: the typical installation directory for ASSP), if
not you will have to modify 'assp' to fit.

Don't forget to set the permissions of assp start stop and assp.pl 
(or best: all scripts) to 755
