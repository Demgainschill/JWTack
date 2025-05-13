#!/bin/bash

## JWTAck for bruteforcing jwt tokens and multiple other features


usage(){
	cat << EOF
		USAGE:
		-h : Usage for JWTack 
		-c : Converts Parses JWT token to json objects
		-w : wordlist to be provided for bruteforcing

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

hashcatBrute(){
	wordlist=$1
	if [[ -n $(which hashcat) ]]; then
		echo "Hashcat exists"
	fi
	
	sig=$(echo $1 | jq .alg | head -n 1 | tr '"' ' ' | tr -d ' ') 
	mode=0
	if [[ -f $wordlist ]]; then
	 case $sig in
		 hs256)
			hashcat -a 0 -m 16500 $wordlist
	       		;;
		 hs384)
 			hashcat -a 0 -m 16600 $wordlist
       			;;
		 hs512)
			hashcat -a 0 -m 16600 $wordlist
			;;
		*)
			echo "mode not found" 
			;;
	
	esac
	fi	
	hs256=16500
	hs384=16600
	hs512=16600
	

	echo "Attempting to use hashcat to bruteforce with $wordlist"

}

while getopts ":hc:w:j:f:" OPTS; do
	case "$OPTS" in
		h)
			usage
			;;
		j)
			jwt=$OPTARG
			if [[ -n $jwt ]]; then
				echo "jwt exists"
			fi
			;;
		f)
			wordlist=$OPTARG
			if [[ -f $wordlist ]]; then
				echo "wordlist exists"
			fi
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
		w)
			if [[ -f $wordlist ]]; then
			"Attempting to crack JWT signature with hashcat"
			hashcatBrute $wordlist
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
