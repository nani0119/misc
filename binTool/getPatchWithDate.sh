#!/bin/bash -
set -o nounset                                  # Treat unset variables as an error

PROJECT_ROOT=`pwd`
RESULT_PATH=$PROJECT_ROOT/result
LOGFILE=$RESULT_PATH/logfile.txt
mkdir -p $RESULT_PATH
echo "" > $LOGFILE

which repo > /dev/null
if [[ $? == 1  ]]
then
	echo "not found repo, please install repo"
	echo "cmd repo not found" >> $LOGFILE
	exit 1
fi

which git > /dev/null
if [[ $? == 1  ]]
then
	echo "not found git, please install git"
	echo "cmd repo not found" >> $LOGFILE
	exit 1
fi


for project_path in `repo forall -c "pwd"`
do
	cd $project_path
	COMMIT=`git log --oneline --since=20/04/2020  --pretty=format:"%p" | tail -1`
	if [[ "$COMMIT" != "" ]]
	then
		echo "===========================>"
		echo "project path:" $project_path
		echo "commit:" $COMMIT
		PATCH_PATH=$RESULT_PATH/$project_path
		echo $PATCH_PATH
		mkdir -p  $PATCH_PATH
		for patch_file in `git format-patch -s $COMMIT`
		do
			echo $patch_file
		    mv $patch_file  $PATCH_PATH
			echo $PATCH_PATH/$patch_file  >> $LOGFILE
	    done
	else
		continue
	fi

done

