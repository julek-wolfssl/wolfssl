#!/bin/bash
  
SCRIPT=`realpath $0`
SCRIPTPATH=`dirname $SCRIPT`

$SCRIPTPATH/client "$@" 2> >(grep --color=auto -P 'processing |Entering SendTls13|Entering SendDtls13|got |Entering SSL_write|Entering SendAlert')

