bash-fix
========

## Official Patch From Apple

On 30 September 2014 Apple made official patches available for the following versions of OS X:

* [Mavericks](http://support.apple.com/kb/DL1769)
* [Mountain Lion](http://support.apple.com/kb/DL1768)
* [Lion](http://support.apple.com/kb/DL1767)

I would encourage people to use those unless new vulnerabilities are found.


## Summary

Download and compile a new version of bash to replace vulnerable one

## Background ##

[Troy Hunt: Everything you need to know about the Shellshock Bash bug](http://www.troyhunt.com/2014/09/everything-you-need-to-know-about.html?m=1)

## How To Install/Use ##

1. [Install Xcode](macappstore://itunes.apple.com/us/app/xcode/id497799835?mt=12) if it is not already installed.

2.	Launch Terminal.app (or iTerm)


3. If this is your first time using Xcode’s command line tools, you will have to agree to the terms and conditions by using 

	`sudo xcodebuild -license`


4.	Run this command 

		curl -sL http://luo.ma/bash-fix.sh | zsh -f

	That’s just a short URL for <https://raw.githubusercontent.com/tjluoma/bash-fix/master/bash-fix.sh> but if you want to use that directly, copy this:

		curl -s https://raw.githubusercontent.com/tjluoma/bash-fix/master/bash-fix.sh | zsh -f
	
4.	Follow prompts

When you are done, `bash --version` should report itself as:

GNU bash, version 3.2.54(1)-release (x86_64-apple-darwin13)

## Troubleshooting: ##

**“build/Release/bash does not exist.”**
:Enter `sudo xcodebuild -license` into Terminal, read and agree to terms, and then re-run the script.



## Sources: 

1.	<http://apple.stackexchange.com/questions/146849/how-do-i-recompile-bash-to-avoid-the-remote-exploit-cve-2014-6271-and-cve-2014-7/146851#146851> 
2.	<http://alblue.bandlem.com/2014/09/bash-remote-vulnerability.html>
