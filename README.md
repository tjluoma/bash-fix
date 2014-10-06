bash-fix
========

## Summary

Download and compile a new version of bash to replace vulnerable one.

Derived from [Alex Blewitt’s original][1] which I first saw when he posted it on [the Apple StackExchange site][2].


## “Didn’t Apple fix this?”

On 30 September 2014 Apple made official patches available for the following versions of OS X:

* [Mavericks][3]
* [Mountain Lion][4]
* [Lion][5]

Apple’s fixed `bash` is `GNU bash, version 3.2.53(1)-release (x86_64-apple-darwin13)`.

As I understand it, that solved the remotely exploitable part of the [shellshock][6] vulnerability. So if that’s all you are worried about, you should be safe after applying the appropriate update from Apple.

**However, other problems are still being found and patched.**

If you are a regular Mac user and aren’t running a Mac server, you probably don’t need to worry about anything beyond Apple’s official fix.

However, I _do_ run a Mac server (at the awesome [MacMiniColo][]) and wanted to keep my version of bash “more current” so I installed
Apple’s fix and then re-ran this script.

I will continue to update this script as I learn of more vulnerabilities. Pull requests for new official patches are always welcome. Thanks to [those who have already contributed][7], including [Rosyna Keller][8] via Twitter.

## Disclaimer

**As always, YMMV, and use _entirely_ at your own risk.**

No warranty expressed or implied for any suitability for any purpose.

If something breaks, you own both pieces and all of the responsibility, and so on.


## How To Install/Use ##

1. Install [Xcode][] if it is not already installed.


2.	Launch **Terminal.app** (or [iTerm](http://iterm2.com))

3. If this is your first time using Xcode’s command line tools, you will have to agree to the terms and conditions by using

	`sudo xcodebuild -license`

4.	Run this command

		curl -sL http://luo.ma/bash-fix.sh | zsh -f

	That’s just a short URL for <https://raw.githubusercontent.com/tjluoma/bash-fix/master/bash-fix.sh> but if you would rather not use the short URL, use this instead:

		curl -s https://raw.githubusercontent.com/tjluoma/bash-fix/master/bash-fix.sh | zsh -f

4.	Follow prompts

When you are done, `bash --version` should report itself as:

**GNU bash, version 3.2.57(1)-release (x86_64-apple-darwin13)**

(or possibly later, if more patches have been added and I forgot to update the README.)

## Troubleshooting: ##

_Error:_ **“build/Release/bash does not exist.”**

_Fix:_ Enter `sudo xcodebuild -license` into Terminal, read and agree to terms, and then re-run the script.




[1]:	http://alblue.bandlem.com/2014/09/bash-remote-vulnerability.html
[2]:	http://apple.stackexchange.com/questions/146849/how-do-i-recompile-bash-to-avoid-the-remote-exploit-cve-2014-6271-and-cve-2014-7/146851#146851
[3]:	http://support.apple.com/kb/DL1769
[4]:	http://support.apple.com/kb/DL1768
[5]:	http://support.apple.com/kb/DL1767
[6]:	http://www.troyhunt.com/2014/09/everything-you-need-to-know-about.html?m=1
[7]:	https://github.com/tjluoma/bash-fix/graphs/contributors
[8]:	https://twitter.com/rosyna/status/518054086050971650


[MacMiniColo]:	http://MacMiniColo.net
[Xcode]:	http://itunes.apple.com/us/app/xcode/id497799835?mt=12
