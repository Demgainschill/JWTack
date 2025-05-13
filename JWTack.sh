#!/bin/bash

## JWTAck for bruteforcing jwt tokens and multiple other features


usage(){
	cat << EOF
		USAGE:
		-h : Usage for JWTack 
		-c : Converts Parses JWT token

EOF
}

jwtCheck(){
	jwt="$(echo $1  | tr '.' '\n' | base64 -d  2>/dev/null )"
	echo $jwt | jq -r . 2>/dev/null

	signature=$(echo $1 | tr '.' ' ' | cut -d ' ' -f 3 )	
	if [[ -n $signature ]]; then
		echo "$(echo "signature=$signature" | awk -F '=' '{print "{\""$1"\": \""$2"\"}"}')"
	else
		echo "No signature found"
	fi		

}

while getopts ":hc:" OPTS; do
	case "$OPTS" in
		h)
			usage
			;;
		c)
			if [[ -n $OPTARG ]]; then
				JWT="$OPTARG"
				jwtCheck $JWT
			else
				echo "No jwt token provided.Exiting..."
				exit 1
			fi
			;;
		\?)
			echo "Invalid Options"
			exit 1
			;;
		:)
			echo "Missing arguments"
			exit 1
			;;
	esac
done

if [[ ! -n $1  ]]; then
	echo "Too less arguments"
	usage
	exit 1
fi

shift $((OPTIND-1))

if [[ $1 -ge 1 ]]; then
	echo "Too many arguments"
	usage
	exit 1
fi
