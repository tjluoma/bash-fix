#!/bin/zsh -f
# recompile bash -
# 	http://apple.stackexchange.com/questions/146849/how-do-i-recompile-bash-to-avoid-the-remote-exploit-cve-2014-6271-and-cve-2014-7/146851#146851
#
# From:	Timothy J. Luoma
# Mail:	luomat at gmail dot com
# Date:	2014-09-25, Updated 2014-09-29

NAME="bash-fix.sh"

	# This should match Xcode in many variations, betas, etc.
XCODE=`find /Applications -maxdepth 1 -type d -iname xcode\*.app -print`

if [[ "$XCODE" == "" ]]
then
	echo "$NAME [FATAL]: Xcode is required, but not installed. Please install Xcode from the Mac App Store."

	open 'macappstore://itunes.apple.com/us/app/xcode/id497799835?mt=12'

	exit 1
fi

zmodload zsh/datetime

function timestamp { strftime "%Y-%m-%d--%H.%M.%S" "$EPOCHSECONDS" }
function log { echo "$NAME [`timestamp`]: $@" | tee -a "$LOG" }

function die
{
	echo "\n$NAME [FATAL]: $@"
	exit 1
}

function msg
{
	echo "\n	$NAME [INFO]: $@"
}

TIME=$(strftime "%Y-%m-%d-at-%H.%M.%S" "$EPOCHSECONDS")

LOG="$HOME/Library/Logs/$NAME.$TIME.txt"

[[ -d "$LOG:h" ]] || mkdir -p "$LOG:h"
[[ -e "$LOG" ]]   || touch "$LOG"


cd "$HOME/Desktop" || cd

mkdir -p bash-fix

cd bash-fix

ORIG_DIR="$PWD"

##################################################################################################

msg "Downloading and uncompressing Apple's 'bash' source code..."

curl --progress-bar -fL https://opensource.apple.com/tarballs/bash/bash-92.tar.gz | tar zxf -

EXIT="$?"

if [ "$EXIT" = "0" ]
then
	msg "Successfully downloaded bash source from Apple.com"
else
	die "curl or tar failed (\$EXIT = $EXIT)"

fi

cd bash-92/bash-3.2

msg "CWD is now $PWD"

##################################################################################################

msg "Downloading and applying bash32-052 from gnu.org..."
curl --progress-bar -fL https://ftp.gnu.org/pub/gnu/bash/bash-3.2-patches/bash32-052 | patch -p0

EXIT="$?"

if [ "$EXIT" = "0" ]
then
	msg "patch bash32-052 successfully applied"
else
	die "patch bash32-052 FAILED"
fi

##################################################################################################

msg "Downloading and applying bash32-053 from gnu.org..."
curl --progress-bar -fL https://ftp.gnu.org/pub/gnu/bash/bash-3.2-patches/bash32-053 | patch -p0

EXIT="$?"

if [ "$EXIT" = "0" ]
then
	msg "patch bash32-053 successfully applied"
else
	die "patch bash32-053 FAILED"
fi

##################################################################################################

msg "Downloading and applying bash32-054 from gnu.org..."
curl --progress-bar -fL https://ftp.gnu.org/pub/gnu/bash/bash-3.2-patches/bash32-054 | patch -p0

EXIT="$?"

if [ "$EXIT" = "0" ]
then
	msg "patch bash32-054 successfully applied"
else
	die "patch bash32-054 FAILED"
fi

##################################################################################################

msg "Downloading and applying bash32-055 from gnu.org..."
curl --progress-bar -fL https://ftp.gnu.org/pub/gnu/bash/bash-3.2-patches/bash32-055 | patch -p0

EXIT="$?"

if [ "$EXIT" = "0" ]
then
	msg "patch bash32-055 successfully applied"
else
	die "patch bash32-055 FAILED"
fi

##################################################################################################

msg "Downloading and applying bash32-056 from gnu.org..."
curl --progress-bar -fL https://ftp.gnu.org/pub/gnu/bash/bash-3.2-patches/bash32-056 | patch -p0

EXIT="$?"

if [ "$EXIT" = "0" ]
then
	msg "patch bash32-056 successfully applied"
else
	die "patch bash32-056 FAILED"
fi


##################################################################################################

msg "Downloading and applying bash32-057 from gnu.org..."
curl --progress-bar -fL https://ftp.gnu.org/pub/gnu/bash/bash-3.2-patches/bash32-057 | patch -p0

EXIT="$?"

if [ "$EXIT" = "0" ]
then
	msg "patch bash32-057 successfully applied"
else
	die "patch bash32-057 FAILED"
fi

##################################################################################################

cd ..

msg "CWD is now $PWD"

echo -n "$NAME is about to run xcodebuild and its output redirected to $ORIG_DIR/xcodebuild.log. If it does not succeed, check the log for error messages.\n\nThis could take a few minutes. Please wait... "

xcodebuild 2>&1 >>| "$ORIG_DIR/xcodebuild.log"

EXIT="$?"

if [ "$EXIT" = "0" ]
then
	msg "xcodebuild exited successfully."

else
	die "xcodebuild failed (\$EXIT = $EXIT). See $ORIG_DIR/xcodebuild.log for details."
	exit 1
fi


	# Play a sound to tell them the build finished
[[ -e /System/Library/Sounds/Glass.aiff ]] && afplay /System/Library/Sounds/Glass.aiff

if [ -e 'build/Release/bash' ]
then
	msg "Here is the _NEW_ version number for bash (must be 3.2.52(1) or later):"

	build/Release/bash --version # GNU bash, version 3.2.54(1)-release (x86_64-apple-darwin13)
else
	die "build/Release/bash does not exist. See $PWD/xcodebuild.log for details."
fi

if [ -e 'build/Release/sh' ]
then
	msg "Here is the _NEW_ version number for sh (must be 3.2.52(1) or later):"

	build/Release/sh --version   # GNU bash, version 3.2.54(1)-release (x86_64-apple-darwin13)

else
	die "build/Release/sh does not exist. See $PWD/xcodebuild.log for details."
fi

####################################################################################
#
# 2014-09-29: disabled test section because it only tests first vulnerability.
# 2014-09-29: TODO: Add tests for each vulnerability to verify it was fixed
#
# 	$NAME: About to run test of new bash:
#
# 	You should see 'hello' but you should NOT see the word 'vulnerable':
#
# Press Return/Enter to run test: "
#
# read PROMPT_TO_CONTINUE
#
# env x='() { :;}; echo vulnerable' build/Release/bash -c 'echo hello' 2>/dev/null


echo "\n\n"

read "?$NAME: Ready to install newly compiled 'bash' and 'sh'? [Y/n]: " ANSWER

case "$ANSWER" in
	N*|n*)
			echo "$NAME: OK, not installing"
			exit 0
	;;
esac


cat <<EOINPUT

$NAME: About to replace the vulnerable versions of /bin/bash and /bin/sh with the new, patched versions.
	The.$TIME ones will be backed up to /bin/bash.$TIME and /bin/sh.$TIME respectively

Please enter your administrator password (if prompted):
EOINPUT

	# This will prompt user for admin password
sudo -v

##################################################################################################

msg "Moving /bin/bash to /bin/bash.$TIME: "
sudo /bin/mv -vf /bin/bash "/bin/bash.$TIME"	|| die "Failed to move /bin/bash to /bin/bash.$TIME"

msg "Installing build/Release/bash to /bin/bash: "
sudo cp -v build/Release/bash /bin/bash

if [ "$?" != "0" ]
then
	sudo mv -vf "/bin/bash.$TIME" /bin/bash
	die "Failed to move build/Release/bash to /bin/bash. Restored /bin/bash.$TIME to /bin/bash"
fi

##################################################################################################

msg "Moving /bin/sh to /bin/sh.$TIME: "
sudo /bin/mv -vf /bin/sh   "/bin/sh.$TIME" 	|| die "Failed to move /bin/sh to /bin/sh.$TIME"

msg "Installing build/Release/sh to /bin/sh: "
sudo cp -v build/Release/sh /bin/sh

if [ "$?" != "0" ]
then
	sudo mv -vf "/bin/sh.$TIME" /bin/sh
	die "Failed to move build/Release/sh to /bin/sh. Restored /bin/sh.$TIME to /bin/sh"
fi

##################################################################################################

msg "Removing executable bit from /bin/bash.$TIME"

sudo /bin/chmod a-x "/bin/bash.$TIME" \
 	|| msg "WARNING: Failed to remove executable bit from /bin/bash.$TIME"

msg "Removing executable bit from /bin/sh.$TIME"

sudo /bin/chmod a-x "/bin/sh.$TIME" \
	|| msg "WARNING: Failed to remove executable bit from /bin/sh.$TIME"

msg "$NAME has finished successfully."


read "?Do you want to move $ORIG_DIR to ~/.Trash/? [Y/n]  " ANSWER

case "$ANSWER" in
	N*|n*)
			echo "$NAME: Not moving $ORIG_DIR."
			exit 0
	;;

	*)
			echo
			mv -vn "$ORIG_DIR" "$HOME/.Trash/$ORIG_DIR:t.$EPOCHSECONDS"
			exit 0
	;;

esac

exit
#
#EOF

