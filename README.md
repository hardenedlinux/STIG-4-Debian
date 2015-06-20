# STIG-4-Debian

##About

This scrpit is use check DISA STIG(Security Technical Implementation Guides) for Debian 8
Porting from DISA RHEL 6 STIG V1 R7.

[DISA RHEL 6 STIG V1 R7](http://iase.disa.mil/stigs/os/unix-linux/Pages/red-hat.aspx)


##Usage

```
#bash check.sh
usage: check.sh [options]

  -c    Output Log with catable colors
  -s    Perform STIG checking with NORMAL output log
  -v    Show version
  -h 	Show this message

Default log file location at /var/log/STIG-Checking-*.log

STIG Check for Debian (v0.1)

Port DISA RHEL 6 STIG V1R7 for Debian
```

##Project Work

* Up to RHEL-06-272 and still working on what's left
