#!/usr/bin/perl

$/="\n";
#for $f ('spamdb','whitelist','dnsbl') {
for $f ('whitelist','dnsbl') {
 print "processing $f\n";
 open(F,"<$f");
 <F>;
 while(<F>) {
  ($k,$v)=split(/[\001\002\n]/,$_);
  #print "$k=$v\n";
  $w{$k}=$v;
  print "$k   \r" if ($c++ & 0xff)==0;
 }
 close F;
 print "finishing $f  \n";
 open(G,">$f.new");
 binmode G;
 print G "\n";
 for (sort keys %w) {
  print G "$_\002$w{$_}\n";
 }
 close G;
 rename($f,"$f.bak");
 rename("$f.new",$f);
 undef %w;
}
