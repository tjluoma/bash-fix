bash-fix
========

## Summary

Download and compile a new version of bash to replace vulnerable one.

## “Didn’t Apple fix this?”

Yes and no.

On 30 September 2014 Apple made official patches available for the following versions of OS X:

* [Mavericks](http://support.apple.com/kb/DL1769)
* [Mountain Lion](http://support.apple.com/kb/DL1768)
* [Lion](http://support.apple.com/kb/DL1767)

However, Apple’s fixed `bash` is `GNU bash, version 3.2.53(1)-release (x86_64-apple-darwin13)` which is still vulnerable to this:

	env '__BASH_FUNC<ls>()'="() { echo Game Over; }" /bin/bash -c ls

**Other problems are still being found and patched.**

As of 2014-10-02, compiling `bash` from this script will build `GNU bash, version 3.2.55(1)-release (x86_64-apple-darwin13)`.

There may _still_ be vulnerabilities in `GNU bash, version 3.2.55(1)-release (x86_64-apple-darwin13)` but I’d rather be current on my Mac servers. 

If you are a regular Mac user and aren’t running a Mac server, you _probably_ don’t need to worry about this and can wait for Apple’s next official update. If you _are_ running a Mac server, you should find some way to stay current, whether it is this script or your own.

(Personally, I installed Apple’s fix and then re-ran this script to have a more current version of `bash`. )

I will continue to update this script as I learn of more vulnerabilities. Pull requests for new official patches are always welcome. Thanks to [those who have already contributed](https://github.com/tjluoma/bash-fix/graphs/contributors).



## Disclaimer

**As always, YMMV, and use _entirely_ at your own risk.**

No warranty expressed or implied for any suitability for any purpose. 

If something breaks, you own both pieces and all of the responsibility, and so on.


## Background ##

[Troy Hunt: Everything you need to know about the Shellshock Bash bug](http://www.troyhunt.com/2014/09/everything-you-need-to-know-about.html?m=1)

## How To Install/Use ##

1. [Install Xcode](macappstore://itunes.apple.com/us/app/xcode/id497799835?mt=12) if it is not already installed.

2.	Launch Terminal.app (or iTerm)


3. If this is your first time using Xcode’s command line tools, you will have to agree to the terms and conditions by using 

	`sudo xcodebuild -license`


4.	Run this command 

		curl -sL http://luo.ma/bash-fix.sh | zsh -f

	That’s just a short URL for <https://raw.githubusercontent.com/tjluoma/bash-fix/master/bash-fix.sh> but if you would rather not use the short URL, use this instead:

		curl -s https://raw.githubusercontent.com/tjluoma/bash-fix/master/bash-fix.sh | zsh -f
	
4.	Follow prompts

When you are done, `bash --version` should report itself as:

**GNU bash, version 3.2.55(1)-release (x86_64-apple-darwin13)**

## Troubleshooting: ##

_Error:_ **“build/Release/bash does not exist.”**

_Fix:_ Enter `sudo xcodebuild -license` into Terminal, read and agree to terms, and then re-run the script.



## Sources: 

1.	<http://apple.stackexchange.com/questions/146849/how-do-i-recompile-bash-to-avoid-the-remote-exploit-cve-2014-6271-and-cve-2014-7/146851#146851> 
2.	<http://alblue.bandlem.com/2014/09/bash-remote-vulnerability.html>
