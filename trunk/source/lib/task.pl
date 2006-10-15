#!/usr/bin/perl

# perl antispam smtp proxy
# (c) 2006 Przemyslaw Czerkas <przemekc@poczta.onet.pl>

# This module implements simple cooperative multitasking
# kernel based on semi-coroutines emulated in pure Perl.

$version='1.2.0';
$modversion=' beta 0';

use bytes; # get rid of anoying 'Malformed UTF-8' messages

# task states: RUN READ WRITE DELAY SUSPEND FINISH
# task priorities: HIGH NORM IDLE
# %Tasks -- available tasks
# @Tasks -- tasks queue
# $CurTaskID -- current task id

use IO::Select;

sub newTask {
 my ($tref,$priority,$class,$suspended)=@_;
 return unless $tref;
 my $tid=++$TaskID;
 my $task=$Tasks{$tid}={};
 $task->{name}=$tref->[0];
 $task->{handler}=$tref->[1];
 $task->{coro}=new Coroutine($task->{handler})->wrap();
 $task->{priority}=$priority||='NORM';
 $task->{state}=$suspended=$suspended ? 'SUSPEND' : 'RUN';
 $task->{class}=$class||='DEFAULT';
 push(@Tasks,$tid);
 $TaskStats{$class}->{created}++;
 return $tid;
}

sub doneTask {
 my $tid=shift;
 return unless defined $tid;
 $tid||=$CurTaskID;
 return unless exists $Tasks{$tid};
 my $task=$Tasks{$tid};
 $task->{state}='FINISH';
}

sub doneAllTasks {
 while (my ($tid,$task)=each(%Tasks)) {
  my $task=$Tasks{$tid};
  $task->{state}='FINISH';
 }
}

sub getTaskState {
 my $tid=shift;
 return unless defined $tid;
 $tid||=$CurTaskID;
 return 0 unless exists $Tasks{$tid};
 my $task=$Tasks{$tid};
 return $task->{state};
}

sub setTaskPriority {
 my ($tid,$priority)=@_;
 return unless defined $tid;
 $tid||=$CurTaskID;
 return unless exists $Tasks{$tid};
 my $task=$Tasks{$tid};
 $task->{priority}=$priority||='NORM';
}

sub suspendTask {
 my $tid=shift;
 return unless defined $tid;
 $tid||=$CurTaskID;
 return unless exists $Tasks{$tid};
 my $task=$Tasks{$tid};
 $task->{state}='SUSPEND' if $task->{state} eq 'RUN';
}

sub resumeTask {
 my $tid=shift;
 return unless defined $tid;
 $tid||=$CurTaskID;
 return unless exists $Tasks{$tid};
 my $task=$Tasks{$tid};
 $task->{state}='RUN' if $task->{state} eq 'SUSPEND';
}

sub waitTaskRead {
 my ($tid,$handle,$timeout)=@_;
 return unless defined $tid;
 $tid||=$CurTaskID;
 return unless exists $Tasks{$tid};
 return if $timeout<0; # negative time not invented yet
 my $task=$Tasks{$tid};
 if ($task->{state} eq 'RUN') {
  $task->{state}='READ';
  $task->{handle}=$handle;
  $task->{timeline}=($AvailHiRes ? Time::HiRes::time() : time-(1e-6))+$timeout;
 }
}

sub waitTaskWrite {
 my ($tid,$handle,$timeout)=@_;
 return unless defined $tid;
 $tid||=$CurTaskID;
 return unless exists $Tasks{$tid};
 return if $timeout<0;
 my $task=$Tasks{$tid};
 if ($task->{state} eq 'RUN') {
  $task->{state}='WRITE';
  $task->{handle}=$handle;
  $task->{timeline}=($AvailHiRes ? Time::HiRes::time() : time-(1e-6))+$timeout;
 }
}

sub waitTaskDelay {
 my ($tid,$timeout)=@_;
 return unless defined $tid;
 $tid||=$CurTaskID;
 return unless exists $Tasks{$tid};
 return if $timeout<0;
 my $task=$Tasks{$tid};
 if ($task->{state} eq 'RUN') {
  $task->{state}='DELAY';
  $task->{timeline}=($AvailHiRes ? Time::HiRes::time() : time-(1e-6))+$timeout;
 }
}

sub getTaskWaitResult {
 my $tid=shift;
 return unless defined $tid;
 $tid||=$CurTaskID;
 return 0 unless exists $Tasks{$tid};
 my $task=$Tasks{$tid};
 return $task->{result};
}

sub doTask {
 my ($kernelTime,$idleTime,$userTime)=(0)x3;
 $KernelStats{calls}++;
 # cpu stats
 if ($CanStatCPU) {
  my $statTime=Time::HiRes::time();
  $kernelTime-=$statTime;
 }
 my $thisTime=$AvailHiRes ? Time::HiRes::time() : time+(1e-6);
 my $timeline=$thisTime+(1e+6);
 # count tasks per state, find nearest timeline
 my ($allCnt,$runCnt,$waitCnt,$delayCnt,$suspendCnt,$finishCnt)=(0)x6;
 my (@rhs,@whs);
 foreach my $tid (@Tasks) {
  next unless exists $Tasks{$tid};
  my $task=$Tasks{$tid};
  if ($task->{state} eq 'RUN') {
   $timeline=$thisTime;
   $runCnt++;
  } elsif ($task->{state} eq 'SUSPEND') {
   $suspendCnt++;
  } elsif ($task->{state} eq 'FINISH') {
   $timeline=$thisTime;
   $finishCnt++;
  } else {
   $timeline=$task->{timeline} if $task->{timeline}<$timeline;
   if ($task->{state} eq 'READ') {
    push(@rhs,$task->{handle});
    $waitCnt++;
   } elsif ($task->{state} eq 'WRITE') {
    push(@whs,$task->{handle});
    $waitCnt++;
   } elsif ($task->{state} eq 'DELAY') {
    $delayCnt++;
   }
  }
  $allCnt++;
 }
 # adjust timeline
 $timeline=$thisTime if $timeline<$thisTime;
 # cpu stats
 if ($CanStatCPU) {
  my $statTime=Time::HiRes::time();
  $kernelTime+=$statTime;
  $idleTime-=$statTime;
 }
 # wait/sleep as much as possible
 my ($rhs,$whs);
 if ($waitCnt) {
  ($rhs,$whs)=IO::Select->select(new IO::Select(@rhs),new IO::Select(@whs),undef,$timeline-$thisTime);
 } elsif ($runCnt || $finishCnt) {
  # empty
 } elsif ($delayCnt) {
  $AvailHiRes ? Time::HiRes::sleep($timeline-$thisTime) : select(undef,undef,undef,$timeline-$thisTime); # emulate sleep
 } elsif ($suspendCnt) {
  sleep(1);
 }
 # cpu stats
 if ($CanStatCPU) {
  my $statTime=Time::HiRes::time();
  $idleTime+=$statTime;
  $kernelTime-=$statTime;
 }
 $thisTime=$AvailHiRes ? Time::HiRes::time() : time+(1e-6);
 # update tasks
 foreach my $tid (@Tasks) {
  next unless exists $Tasks{$tid};
  my $task=$Tasks{$tid};
  if ($task->{state} eq 'RUN') { # update runable task
   # empty
  } elsif ($task->{state} eq 'READ') { # update readable task
   if ($task->{timeline}<=$timeline) {
    $task->{result}=0;
    $task->{state}='RUN';
   }
   foreach my $h (@$rhs) {
    if ($task->{handle}==$h) {
     $task->{result}=1;
     $task->{state}='RUN';
     last;
    }
   }
  } elsif ($task->{state} eq 'WRITE') { # update writable task
   if ($task->{timeline}<=$timeline) {
    $task->{result}=0;
    $task->{state}='RUN';
   }
   foreach my $h (@$whs) {
    if ($task->{handle}==$h) {
     $task->{result}=1;
     $task->{state}='RUN';
     last;
    }
   }
  } elsif ($task->{state} eq 'DELAY') { # update delayed task
   if ($task->{timeline}<=$thisTime) {
    $task->{result}=1;
    $task->{state}='RUN';
   }
  } elsif ($task->{state} eq 'SUSPEND') { # update suspended task
   # empty
  } elsif ($task->{state} eq 'FINISH') { # update finished task
   # empty
  }
 }
 # rearrange queue by task priority
 my (@high,@norm,@idle,@wait,@suspend);
 foreach my $tid (@Tasks) {
  next unless exists $Tasks{$tid};
  my $task=$Tasks{$tid};
  if ($task->{state} eq 'RUN') {
   if ($task->{priority} eq 'HIGH') {
    push(@high,$tid);
   } elsif ($task->{priority} eq 'NORM') {
    push(@norm,$tid);
   } else { # IDLE priority
    push(@idle,$tid);
   }
  } elsif ($task->{state} eq 'SUSPEND') {
   push(@suspend,$tid);
  } elsif ($task->{state} eq 'FINISH') {
   my $class=$task->{class};
   $TaskStats{$class}->{finished}++;
   delete $Tasks{$tid}; # dispose
  } else { # READ WRITE DELAY tasks
   push(@wait,$tid);
  }
 }
 @Tasks=(@high,@norm,@idle,@wait,@suspend);
 $KernelStats{max_queue}=scalar @Tasks if @Tasks>$KernelStats{max_queue};
 $KernelStats{max_high_queue}=scalar @high if @high>$KernelStats{max_high_queue};
 $KernelStats{max_norm_queue}=scalar @norm if @norm>$KernelStats{max_norm_queue};
 $KernelStats{max_idle_queue}=scalar @idle if @idle>$KernelStats{max_idle_queue};
 $KernelStats{max_wait_queue}=scalar @wait if @wait>$KernelStats{max_wait_queue};
 $KernelStats{max_suspend_queue}=scalar @suspend if @suspend>$KernelStats{max_suspend_queue};
 # schedule task
 my $tid=shift @Tasks; $allCnt-- if $allCnt; # dequeue task
 if (exists $Tasks{$tid}) {
  my $task=$Tasks{$tid};
  if ($task->{state} eq 'RUN') {
   my $class=$task->{class};
   $TaskStats{$class}->{calls}++;
   $CurTaskID=$tid;
   my @ret=$task->{coro}->($kernelTime,$userTime); # run task
   # cpu stats
   if ($CanStatCPU) {
    $TaskStats{$class}->{user_time}+=$userTime;
    $TaskStats{$class}->{min_user_time}=$userTime if $userTime<$TaskStats{$class}->{min_user_time} || !$TaskStats{$class}->{min_user_time};
    $TaskStats{$class}->{max_user_time}=$userTime if $userTime>$TaskStats{$class}->{max_user_time};
   }
   $CurTaskID=-1;
   $task->{state}='FINISH' unless @ret; # doneTask
  }
  push(@Tasks,$tid); $allCnt++; # enqueue task
 }
 # cpu stats
 if ($CanStatCPU) {
  my $statTime=Time::HiRes::time();
  $kernelTime+=$statTime;
  $KernelStats{kernel_time}+=$kernelTime;
  $KernelStats{min_kernel_time}=$kernelTime if $kernelTime && $kernelTime<$KernelStats{min_kernel_time} || !$KernelStats{min_kernel_time};
  $KernelStats{max_kernel_time}=$kernelTime if $kernelTime>$KernelStats{max_kernel_time};
  $KernelStats{idle_time}+=$idleTime;
  $KernelStats{user_time}+=$userTime;
 }
 return $allCnt;
}

sub jump {
 goto shift if defined $_[0];
}

sub cede {
 if ($_[1]) {
  # loop-mode, auto-skip some cedes
  $Tasks{$CurTaskID}->{skip_cede}||=1;
  goto $_[0] if ++$Tasks{$CurTaskID}->{cedes} % $Tasks{$CurTaskID}->{skip_cede};
  my $time=$AvailHiRes ? Time::HiRes::time() : time;
  my $interval=$time-$Tasks{$CurTaskID}->{last_cede};
  my $resolution=$AvailHiRes ? 0.1 : 1;
  if ($interval>=2*$resolution) {
   $Tasks{$CurTaskID}->{skip_cede}>>=1;
  } elsif ($interval<$resolution) {
   $Tasks{$CurTaskID}->{skip_cede}<<=1;
  }
  $Tasks{$CurTaskID}->{last_cede}=$time;
 } else {
  $Tasks{$CurTaskID}->{last_cede}=$Tasks{$CurTaskID}->{skip_cede}=$Tasks{$CurTaskID}->{cedes}=0;
 }
 return Coroutine::yield($_[0],[1]);
}


sub call {
 return Coroutine::call($_[0],$_[1]);
}

{
####################################################################################
# This module simulates the semi-coroutine (asymmetric coroutine / Python generator)
# language contruct in pure Perl. Simply, a 'semi-coroutine' is a subroutine
# that suspends itself in the middle of execution, returns a value,
# can be resumed at the same point of execution at a later time.
#
# (c) 1998-2004, David Manura. http://math2.org/david/contact.
# This module is licensed under the same terms as Perl itself.

package Coroutine;

sub new {
 my ($class,$sub)=@_;
 my $self=bless {},$class;
 %$self=(stack=>[[$sub,undef]]);
 return $self;
}

sub call {
 my ($from_label,$to_sub)=@_;
 return bless [$from_label,$to_sub],'Coroutine::CALL';
}

sub yield {
 my ($from_label,$retval)=@_;
 return bless [$from_label,$retval],'Coroutine::YIELD';
}

sub wrap {
 my $self=shift;
 my $stack=$self->{stack};
 return sub {
  my @ret;
  while (1) {
   my ($sub,$label)=@{$stack->[@$stack-1]};
   # cpu stats
   my $statTime=-Time::HiRes::time() if $main::CanStatCPU;
   # call coroutine sub
   @ret=$sub->($label,@ret); # support return value
   # cpu stats
   if ($main::CanStatCPU) {
    $statTime+=Time::HiRes::time();
    $_[1]+=$statTime;
    $_[0]-=$statTime;
    if ($statTime>0.5) {
     if ($sub==$main::Tasks{$main::CurTaskID}->{handler}) {
      main::mlog(0,'excessive time: '.(main::formatTimeInterval($statTime,1)).' in '.($main::Tasks{$main::CurTaskID}->{name}).'()'.($label ? " at $label":''));
     } else {
      my $found;
      while (my ($k,$v)=each(%{$main::Tasks{$main::CurTaskID}})) {
       next unless ref($v) eq 'ARRAY';
       next unless $v->[1]==$sub;
       main::mlog(0,'excessive time: '.(main::formatTimeInterval($statTime,1))." in $k()".($label ? " at $label":''));
       $found=1;
      }
      main::mlog(0,'excessive time: '.(main::formatTimeInterval($statTime,1))." in $sub unknown()".($label ? " at $label":'')) unless $found;
     }
    }
   }
   if (ref($ret[0]) eq 'Coroutine::CALL') {
    $stack->[@$stack-1]->[1]=$ret[0]->[0];
    push(@$stack,[$ret[0]->[1],undef]);
   } elsif (ref($ret[0]) eq 'Coroutine::YIELD') {
    $stack->[@$stack-1]->[1]=$ret[0]->[0];
    return @{$ret[0]->[1]};
   } else { # end of sub
    if (@$stack==1) {
     undef $stack->[0]->[1]; # reset label
     return;
    }
    pop @$stack;
   }
  }
 }
}

}

1;