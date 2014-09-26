#!/bin/zsh -f
# recompile bash -
# 	http://apple.stackexchange.com/questions/146849/how-do-i-recompile-bash-to-avoid-the-remote-exploit-cve-2014-6271-and-cve-2014-7/146851#146851
#
# From:	Timothy J. Luoma
# Mail:	luomat at gmail dot com
# Date:	2014-09-25

NAME="$0:t:r"

if [[ ! -d /Applications/Xcode.app && ! -d /Applications/Xcode6-Beta4.app ]]
then
	echo "$NAME: Xcode is required, but not installed. Please install Xcode from the Mac App Store."

	open 'macappstore://itunes.apple.com/us/app/xcode/id497799835?mt=12'

	exit 1

fi



cd "$HOME/Desktop" || cd

mkdir bash-fix

cd bash-fix

echo "$NAME: Downloading and uncompressing Apple's 'bash' source code..."

curl --progress-bar -fL https://opensource.apple.com/tarballs/bash/bash-92.tar.gz | tar zxf -

EXIT="$?"

if [ "$EXIT" != "0" ]
then
	echo "$NAME: curl or tar failed (\$EXIT = $EXIT)"

	exit 1
fi

cd bash-92/bash-3.2

echo "$NAME: CWD is now $PWD"
echo "$NAME: Downloading and applying bash patch from gnu.org..."

curl --progress-bar -fL https://ftp.gnu.org/pub/gnu/bash/bash-3.2-patches/bash32-052 | patch -p0

EXIT="$?"

if [ "$EXIT" != "0" ]
then
	echo "$NAME: curl or patch failed (\$EXIT = $EXIT)"

	exit 2
fi


cd ..

echo "$NAME: CWD is now $PWD"

cat <<EOINPUT

$NAME: about to run xcodebuild:
	(NOTE: it is completely normal to see A LOT OF messages after this.
	 As long as you see '** BUILD SUCCEEDED **' at the end, you are OK.
	 Please be patient, this WILL take a few minutes...)

EOINPUT

xcodebuild 2>&1 | tee -a xcodebuild.log

EXIT="$?"

if [ "$EXIT" != "0" ]
then

	echo "$NAME: xcodebuild failed (\$EXIT = $EXIT)"

	exit 1
fi

echo "$NAME: Here is the new version number for the version of bash that you just built (must be 3.2.52(1) or later):"

build/Release/bash --version # GNU bash, version 3.2.52(1)-release

echo "\n\n$NAME: Here is the new version number for the version of sh that you just built (must be 3.2.52(1) or later):"

build/Release/sh --version   # GNU bash, version 3.2.52(1)-release

echo "

####################################################################################
####################################################################################
####################################################################################

	$NAME: about to test new bash.

	You should see 'hello' but you should NOT see the word 'vulnerable':

"

env x='() { :;}; echo vulnerable' build/Release/bash -c 'echo hello' 2>/dev/null



read "?$NAME: Ready to install newly compiled 'bash' and 'sh'? (will require admin password) [Y/n]: " ANSWER

case "$ANSWER" in
	N*|n*)
			echo "$NAME: OK, not installing"
			exit 0
	;;
esac


cat <<EOINPUT

$NAME: About to replace the vulnerable versions of /bin/bash and /bin/sh with the new, secure versions.
	The old ones will be backed up to /bin/bash.old and /bin/sh.old respectively

Please enter your administrator password if prompted:

EOINPUT

sudo -v

sudo cp -v /bin/bash /bin/bash.old && \
	sudo /bin/chmod a-x /bin/bash.old && \
		sudo cp -v /bin/sh /bin/sh.old && \
			sudo /bin/chmod a-x /bin/sh.old && \
				sudo cp -v build/Release/bash /bin/bash && \
					sudo cp -v build/Release/sh /bin/sh

EXIT="$?"

if [ "$EXIT" = "0" ]
then
	echo "$NAME: Finished successfully"
	exit 0

else
	echo "$NAME: failed (\$EXIT = $EXIT)"

	exit 1
fi


exit
#
#EOF

