#!/usr/bin/perl

# perl antispam smtp proxy
# (c) 2006 Przemyslaw Czerkas <przemekc@poczta.onet.pl>

# This module implements simple cooperative multitasking
# kernel based on semi-coroutines emulated in pure Perl.

$version='1.2.0';
$modversion=' beta 0';

use bytes; # get rid of anoying 'Malformed UTF-8' messages

# task states: RUN READ WRITE DELAY SUSPEND
# task priorities: HIGH NORM IDLE
# %Tasks -- available tasks
# @Tasks -- tasks queue
# $CurTaskID -- current task id

use IO::Select;

sub newTask {
 my ($handler,$priority,$class,$suspended)=@_;
 return unless $handler;
 my $tid=++$TaskID;
 my $task=$Tasks{$tid}={};
 $task->{handler}=$handler;
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
 my $class=$task->{class};
 delete $Tasks{$tid};
 $TaskStats{$class}->{finished}++;
}

sub doneAllTasks {
 while (my ($tid,$task)=each(%Tasks)) {
  my $class=$task->{class};
  delete $Tasks{$tid};
  $TaskStats{$class}->{finished}++;
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
 my ($tid,$fh,$timeout)=@_;
 return unless defined $tid;
 $tid||=$CurTaskID;
 return unless exists $Tasks{$tid};
 return if $timeout<0; # negative time not invented yet
 my $task=$Tasks{$tid};
 if ($task->{state} eq 'RUN') {
  $task->{state}='READ';
  $task->{fh}=$fh;
  $task->{timeline}=($AvailHiRes ? Time::HiRes::time() : time-(1e-6))+$timeout;
 }
}

sub waitTaskWrite {
 my ($tid,$fh,$timeout)=@_;
 return unless defined $tid;
 $tid||=$CurTaskID;
 return unless exists $Tasks{$tid};
 return if $timeout<0;
 my $task=$Tasks{$tid};
 if ($task->{state} eq 'RUN') {
  $task->{state}='WRITE';
  $task->{fh}=$fh;
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
 my ($allCnt,$runCnt,$waitCnt,$delayCnt,$suspendCnt)=(0)x5;
 my (@rfhs,@wfhs);
 foreach my $tid (@Tasks) {
  next unless exists $Tasks{$tid};
  $allCnt++;
  my $task=$Tasks{$tid};
  if ($task->{state} eq 'SUSPEND') {
   $suspendCnt++;
  } elsif ($task->{state} eq 'RUN') {
   $timeline=$thisTime;
   $runCnt++;
  } else {
   $timeline=$task->{timeline} if $task->{timeline}<$timeline;
   if ($task->{state} eq 'READ') {
    push(@rfhs,$task->{fh});
    $waitCnt++;
   } elsif ($task->{state} eq 'WRITE') {
    push(@wfhs,$task->{fh});
    $waitCnt++;
   } elsif ($task->{state} eq 'DELAY') {
    $delayCnt++;
   }
  }
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
 my ($rfhs,$wfhs);
 if ($waitCnt) {
  ($rfhs,$wfhs)=IO::Select->select(new IO::Select(@rfhs),new IO::Select(@wfhs),undef,$timeline-$thisTime);
 } elsif ($runCnt) {
  # empty
 } elsif ($delayCnt) {
  $AvailHiRes ? Time::HiRes::sleep($timeline-$thisTime) : select(undef,undef,undef,$timeline-$thisTime); # emulate sleep
 } elsif ($suspendCnt) {
  sleep(1);
 }

##
##print "$waitCnt,$runCnt,$delayCnt,$suspendCnt\n";

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
   foreach my $fh (@$rfhs) {
    if ($task->{fh}==$fh) {
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
   foreach my $fh (@$wfhs) {
    if ($task->{fh}==$fh) {
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
   my @ret=$task->{handler}->($kernelTime,$userTime); # run task
   # cpu stats
   if ($CanStatCPU) {
    $TaskStats{$class}->{user_time}+=$userTime;
    $TaskStats{$class}->{min_user_time}=$userTime if $userTime<$TaskStats{$class}->{min_user_time} || !$TaskStats{$class}->{min_user_time};
    $TaskStats{$class}->{max_user_time}=$userTime if $userTime>$TaskStats{$class}->{max_user_time};
   }
   $CurTaskID=-1;
   if (@ret) {
    push(@Tasks,$tid); $allCnt++; # enqueue task
   } else {
    # task might have been deleted outside
    if (exists $Tasks{$tid}) { 
     delete $Tasks{$tid}; # doneTask
     $TaskStats{$class}->{finished}++;
    }
   }
  } else {
   push(@Tasks,$tid); $allCnt++; # enqueue task
  }
 }
 # cpu stats
 if ($CanStatCPU) {
  my $statTime=Time::HiRes::time();
  $kernelTime+=$statTime;
  $KernelStats{kernel_time}+=$kernelTime;
  $KernelStats{min_kernel_time}=$kernelTime if $kernelTime<$KernelStats{min_kernel_time} || !$KernelStats{min_kernel_time};
  $KernelStats{max_kernel_time}=$kernelTime if $kernelTime>$KernelStats{max_kernel_time};
  $KernelStats{idle_time}+=$idleTime;
  $KernelStats{user_time}+=$userTime;
 }
 return $allCnt;
}

sub coro {
 return new Coroutine($_[0])->wrap();
}

sub jump {
 goto shift if defined $_[0];
}

sub cede {
 # if $_[1] is set, cede only on n-th call
 goto $_[0] if $_[1] && ++$Tasks{$CurTaskID}->{cedes} % $_[1];
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
   if ($main::CanStatCPU) {
    my $statTime=Time::HiRes::time();
    $_[0]+=$statTime;
    $_[1]-=$statTime;
   }
   # call coroutine sub
   @ret=$sub->($label,@ret); # support return value
   # cpu stats
   if ($main::CanStatCPU) {
    my $statTime=Time::HiRes::time();
    $_[1]+=$statTime;
    $_[0]-=$statTime;
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