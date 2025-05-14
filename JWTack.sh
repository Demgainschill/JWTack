#!/bin/bash

## JWTAck for bruteforcing jwt tokens and a bunch of other features


usage(){
	cat << EOF
		USAGE: ./JWTack [-h|-c|-w|-j|-f|-e]
           -h            : Usage for JWTack 
	   -c [jwt]      : Converts Parses JWT token to json objects
	   -w [wordlist] : wordlist to be provided for bruteforcing
	   -j [jwt]	 : jwt token to be used together with -f inorder to bruteforce with hashcat 
	   -f [file] 	 : dictionary wordlist file to be provided inorder to crack with hashcat ( to be used with -j )
	   -e [argument] : encode argument with base64 (without newline)
	   
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
	jwt=$2
		
	if [[ -n $(which hashcat) ]]; then
		echo "Hashcat exists"
	else
		echo "Installing hashcat for apt users can be installed using your package managers."
		apt-get install hashcat 
		if [[ $? -eq 1 ]]; then
			echo "Errors encountered while installing hashcat use distro specific package manager to install hashcat then run again"
		exit 1
		fi
	fi
	jwttok=$2
	jwt="$(echo $jwt | tr '.' '\n' | base64 -d )"
	sig=$(echo $jwt | jq .alg | head -n 1 | tr '"' ' ' | tr -d ' ')
	
	if [[ $? -eq 1 ]]; then
		echo "Errors Encountered. Exiting.."
		exit 1
	fi
	mode=0
	if [[ -f $wordlist ]]; then
	 case $sig in
		 HS256)
			hashcat -a 0 -m 16500 $jwttok $wordlist
	       		;;
		 HS384)
 			hashcat -a 0 -m 16600 $jwttok $wordlist
       			;;
		 HS512)
			hashcat -a 0 -m 16600 $jwttok $wordlist
			;;
		*)
			echo "mode not found. Exiting.."
			exit 1
			;;
	
	esac
	fi	
	hs256=16500
	hs384=16600
	hs512=16600
	

	echo "Attempting to use hashcat to bruteforce with $wordlist"

}

jwt=0
wordlist=0


while getopts ":hc:w:j:f:e:" OPTS; do
	case "$OPTS" in
		h)
			usage
			;;
		e)
			secret=$OPTARG
			if [[ -n $secret ]]; then
				echo "Encoded argument in base64" 
				echo -n "$secret" | base64	
			fi
			;;
		j)
			jwttok=$OPTARG
			if [[ -n $jwttok ]]; then
				jwt=1
				
			else
				echo "No JWT provided. Exiting"
				exit 1
			fi
			;;
		f)
			wordlist=$OPTARG
			if [[ -f $wordlist ]]; then
				wordlist=1
				bruteFile=$OPTARG
			else
				echo "Is not a file. Exiting"
				exit 1
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


if [[ $jwt -eq 1 ]] && [[ $wordlist -eq 1 ]]; then 
	echo "Both jwt and wordlist activated"
	hashcatBrute $bruteFile $jwttok
fi 2>/dev/null

#if [[ $wordlist -eq 1 ]] || [[ $jwt -eq 1 ]]; then 
#	echo "Only one arg wordlist or jwt provided. Exiting"
#	exit 1
#fi

shift $((OPTIND-1))

if [[ $1 -ge 1 ]]; then
	echo "Too many arguments"
	usage
	exit 1
fi
