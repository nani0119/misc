#!/bin/bash -
#===============================================================================
#
#          FILE: od_array.sh
#
#         USAGE: ./od_array.sh
#
#   DESCRIPTION: 
#
#       OPTIONS: ---
#  REQUIREMENTS: ---
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: YOUR NAME (), 
#  ORGANIZATION: 
#       CREATED: 06/22/2020 06:58:45 PM
#      REVISION:  ---
#===============================================================================

set -o nounset                                  # Treat unset variables as an error
# $0 objname < in > out

objname=${1:-objname}
# insert 
# replace
# replace the last ,
# append
od -A n -v -t x1 | sed -e '1i\
const unsigned char '$objname'[] = {
s/\([0-9a-f][0-9a-f]\) */0x\1,/g
$s/,$//
$a\
};
'
