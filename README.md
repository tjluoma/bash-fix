bash-fix
========

Download and compile a new version of bash to replace vulnerable one

## Background ##

[Troy Hunt: Everything you need to know about the Shellshock Bash bug](http://www.troyhunt.com/2014/09/everything-you-need-to-know-about.html?m=1)

## How To Install/Use ##

1.	Launch Terminal.app (or iTerm)

2.	Run this command 

		curl -sL http://luo.ma/bash-fix.sh | zsh -f

	That’s just a short URL for <https://raw.githubusercontent.com/tjluoma/bash-fix/master/bash-fix.sh> but if you want to use that directly, copy this:

		curl -s https://raw.githubusercontent.com/tjluoma/bash-fix/master/bash-fix.sh | zsh -f
	
3.	Follow prompts

## Sources: 

1.	<http://apple.stackexchange.com/questions/146849/how-do-i-recompile-bash-to-avoid-the-remote-exploit-cve-2014-6271-and-cve-2014-7/146851#146851> 
2.	<http://alblue.bandlem.com/2014/09/bash-remote-vulnerability.html>
