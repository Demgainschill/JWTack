#!/bin/bash

## JWTAck for bruteforcing jwt tokens and a bunch of other features

b=$(tput setaf 4)
r=$(tput setaf 1)
g=$(tput setaf 10)
y=$(tput setaf 3)
reset=$(tput sgr0)
c=$(tput setaf 14)
o=$(tput setaf 208)

usage(){
	cat << EOF
${r}   ▗▖▗▖ ▗▖▗▄▄▄▖▗▄▖  ▗▄▄▖▗▖ ▗▖ ${reset}
${r}   ▐▌▐▌ ▐▌  █ ▐▌ ▐▌▐▌   ▐▌▗▞▘ ${reset}
${r}   ▐▌▐▌ ▐▌  █ ▐▛▀▜▌▐▌   ▐▛▚▖  ${reset}
${r}▗▄▄▞▘▐▙█▟▌  █ ▐▌ ▐▌▝▚▄▄▖▐▌ ▐▌ ${reset}
${r}                              ${reset}
	
	${b}USAGE${reset}: ./${g}JWTack${reset} [${y}-h${reset}|${y}-c${reset}|${y}-w${reset}|${y}-j${reset}|${y}-f${reset}|${y}-e${reset}|${y}-g${reset}|${y}-s${reset}] [${b}jwt${reset}|${b}wordlist${reset}|${b}file${reset}|${b}base64${reset}|${b}secret${reset}]
	   ${y}-c${reset} [${b}jwt${reset}]      : ${c}Converts Parses JWT token to json objects ${reset}
	   ${y}-w${reset} [${b}wordlist${reset}] : ${c}wordlist to be provided for bruteforcing ${reset}
	   ${y}-j${reset} [${b}jwt${reset}]	 : ${c}jwt token to be used together with${reset} ${y}-f${reset}${c} inorder to bruteforce with hashcat ${reset}
	   ${y}-f${reset} [${b}file${reset}] 	 : ${c}dictionary wordlist file to be provided inorder to crack with hashcat${reset} ( ${o}to be used with${reset} ${y}-j${reset} )
	   ${y}-e${reset} [${b}argument${reset}] : ${c}encode argument with base64${reset} (${o}without newline${reset})
	   ${y}-g${reset} [${b}base64${reset}]   : ${c}generate new symmetric key using openssl ${reset}
	   ${y}-s${reset} [${b}secret${reset}]   : ${c}Create JWT token using secret header and payload ${reset} 
	   ${y}-h${reset}            : ${c}Usage for JWTack ${reset}
      ${g}JWT Creation Options${reset}:
                         ${y}secret${reset} – ${c}HMAC secret *or* PEM key${reset}
                         ${y}hdr${reset}    – ${c}JSON header${reset} (${o}string or file${reset})
                         ${y}pld${reset}    – ${c}JSON payload${reset} (${o}string or file${reset})

${b}Examples${reset}:
	./${g}JWTack.sh${reset} ${y}-s${reset} '${o}secret${reset}' '${g}{${reset}"${b}alg${reset}":"${g}HS256${reset}","${b}typ${reset}":"${g}JWT${reset}"${g}}${reset}'${reset} ${c}'${g}{${reset}"${b}sub${reset}":"${g}24682468${reset}","${b}name${reset}":"${g}Demgainschill${reset}"${g}}${reset}'${reset}  
	./${g}JWTack${reset} ${y}-s${reset} ${o}private.pem${reset} ${c}header.json${reset} ${c}payload.json${reset}
EOF
	   
}

jwtCheck(){
	echo -e "\n${y}jwt decoded${reset}\n"
	jwt="$(echo $1  | tr '.' '\n' | base64 -d  2>/dev/null )"
	echo $jwt | jq -r . 2>/dev/null
	signature=$(echo $1 | tr '.' ' ' | cut -d ' ' -f 3 )	
	if [[ -n $signature ]]; then
		echo "$(echo "signature=$signature" | awk -F '=' '{print "{\""$1"\": \""$2"\"}"}')"
	else
		echo "${r}No signature found${reset}"
	fi		

}

gentester(){

	key_bytes=$(openssl rand 16)
	key_base64url=$(echo -n "$key_bytes" | base64 | tr '+/' '-_' | tr -d '=')
	key_base64url=$1
	kid="key-123"
	jwk=$(jq -c -n --arg k "$key_base64url" --arg kid "$kid" \
  		'{kty: "oct", kid: $kid, k: $k}')

	jwt="$2"

	IFS='.' read -r header payload signature <<< "$jwt"

	header_json=$(echo -n "$header" | tr '_-' '/+' | base64 -d 2>/dev/null || echo -n "$header" | tr '_-' '/+' | base64 -d -w 0)

	new_header_json=$(echo -n "$header_json" | jq -c \
  	--arg kty "oct" \
  	--arg kid "$kid" \
  	'. + {alg: "HS256", kty: $kty, kid: $kid, k}')  

	new_header=$(echo -n "$new_header_json" | base64 | tr '+/' '-_' | tr -d '=')

	new_payload="$payload"

	unsigned_token="$new_header.$new_payload"
	new_signature=$(echo -n "$unsigned_token" | openssl dgst -binary -sha256 -hmac "$key_bytes" | base64 | tr '+/' '-_' | tr -d '=')

	new_jwt="$new_header.$new_payload.$new_signature"

	echo "${g}New JWT:${reset} $new_jwt"
	echo "${g}JWK:${reset} $jwk"
	echo "${g}Symmetric key (base64url):${reset} $key_base64url"
}

hashcatBrute(){
	wordlist=$1
	jwt=$2
		
	if [[ -n $(which hashcat) ]]; then
		echo "${g}Hashcat exists${reset}"
	else
		echo "${y}Installing hashcat for apt users can be installed using your package managers.${reset}"
		apt-get install hashcat 
		if [[ $? -eq 1 ]]; then
			echo "${r}Errors encountered while installing hashcat use distro specific package manager to install hashcat then run again${reset}"
		exit 1
		fi
	fi
	jwttok=$2
	jwt="$(echo $jwt | tr '.' '\n' | base64 -d )"
	sig=$(echo $jwt | jq .alg | head -n 1 | tr '"' ' ' | tr -d ' ')
	
	if [[ $? -eq 1 ]]; then
		echo "${r}Errors Encountered. Exiting..${reset}"
		exit 1
	fi
	mode=0
	if [[ -f $wordlist ]]; then
	 case $sig in
		 HS256)
		
			echo "${y}Attempting to use hashcat to bruteforce with $wordlist${reset}"
		 	 hashcat -a 0 -m 16500 $jwttok $wordlist --force
	       		;;
		 HS384)
			
			echo "${y}Attempting to use hashcat to bruteforce with $wordlist${reset}"
 			hashcat -a 0 -m 16600 $jwttok $wordlist --force
       			;;
		 HS512)
			
			echo "${y}Attempting to use hashcat to bruteforce with $wordlist${reset}"
			hashcat -a 0 -m 16600 $jwttok $wordlist --force
			;;
		*)
			echo "${r}mode not found. Exiting..${reset}"
			exit 1
			;;
	
	esac
	fi	
	hs256=16500
	hs384=16600
	hs512=16600
	


}

genSymmetric(){
	secret=$1
	jwt=$2
	
	newKey=$(openssl rand -base64 32)


	IFS='.' read -r header payload signature <<< "$jwt"

	newSignature=$(echo -n "$header.$payload" | openssl dgst -binary -sha256 -hmac "$new_key" | base64 | tr '+/' '-_' | tr -d '=')

	newJwt="$header.$payload.$newSignature"

	echo "${g}New JWT:${reset} $newJwt"
	echo "${g}New key:${reset} $newKey"	
}

jwt() {
  local secret="$1" header="$2" payload="$3"

  if [[ -z $secret || -z $header || -z $payload ]]; then
    cat <<'EOF'
Usage:  jwt <secret|keyfile> <header> <payload>

  <secret|keyfile>  HMAC secret string   – for HS256/384/512
                    PEM private key file – for RS256/384/512
  <header>          JSON string or path to JSON file
  <payload>         JSON string or path to JSON file

Examples:
  jwt 'my$ecret'  '{"alg":"HS256","typ":"JWT"}'  '{"sub":"123","name":"John"}'
  jwt ./rsa_key.pem  header.json  payload.json
EOF
    return 1
  fi

  [[ -f $header  ]] && header=$(<"$header")
  [[ -f $payload ]] && payload=$(<"$payload")

  b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '=\n'; }

  local enc_header enc_payload data signature
  enc_header=$(printf '%s' "$header"  | b64url)
  enc_payload=$(printf '%s' "$payload" | b64url)
  data="$enc_header.$enc_payload"

  local alg
  alg=$(grep -oE '"alg"[[:space:]]*:[[:space:]]*"[^"]+"' <<<"$header" \
        | head -1 | sed -E 's/.*"alg"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')

  case "$alg" in
    HS256|HS384|HS512)
      local sha="${alg:2}"      # 256 / 384 / 512
      signature=$(printf '%s' "$data" |
                  openssl dgst -sha$sha -mac HMAC -macopt "key:$secret" -binary |
                  b64url)
      ;;
    RS256|RS384|RS512)
      local sha="${alg:2}"
      [[ ! -f $secret ]] && { echo "${r}RSA mode: secret must be a PEM key file${reset}"; return 1; }
      signature=$(printf '%s' "$data" |
                  openssl dgst -sha$sha -sign "$secret" -binary |
                  b64url)
      ;;
    none)
      signature='' ;; 
    *)
      echo "${r}Unsupported alg${reset} \"$alg\""; return 1 ;;
  esac

  printf "${g}\nJWT (%s):${reset}\n%s.%s\n" "$alg" "$data" "$signature"
}



jwt=0
wordlist=0


while getopts ":hc:w:j:f:e:g:s:" OPTS; do
	case "$OPTS" in
		h)
			usage
			;;
		s)
		      secret="$OPTARG"
		      header="${!OPTIND}";  (( OPTIND++ ))
      		      payload="${!OPTIND}"; (( OPTIND++ ))

      		      if [[ -z $header || -z $payload ]]; then
                            echo "-s needs <secret> <header> <payload>"
        	            usage; exit 1
                      fi

			      jwt "$secret" "$header" "$payload"
      			      exit 
                      ;;
		g)
			secret="$OPTARG"
			if [[ -n $secret ]]; then
				echo "${r}Must be used with${reset} ${y}-j${reset}${r} flag${reset}"
				generate=1
			fi
			;;
		e)
			secret=$OPTARG
			if [[ -n $secret ]]; then
				echo "${g}Encoded argument in base64${reset} ( ${o}With no newline \n${reset} )" 
				echo -n "$secret" | base64	
			fi
			;;
		j)
			jwttok=$OPTARG
			if [[ -n $jwttok ]]; then
				jwt=1
				
			else
				echo "${r}No JWT provided. Exiting${reset}"
				exit 1
			fi
			;;
		f)
			wordlist=$OPTARG
			if [[ -f $wordlist ]]; then
				wordlist=1
				bruteFile=$OPTARG
			else
				echo "${r}Is not a file. Exiting..${reset}"
				exit 1
			fi
			;;
		c)
			if [[ -n $OPTARG ]]; then
				JWT="$OPTARG"
				jwtCheck $JWT
			else
				echo "${r}No jwt token provided.Exiting...${reset}"
				exit 1
			fi
			;;
		w)
			if [[ -f $wordlist ]]; then
			"${y}Attempting to crack JWT signature with hashcat${reset}"
			hashcatBrute $wordlist
			fi
			;;
		\?)
			echo "${r}Invalid Option. Exiting..${reset}"
			exit 1
			;;
		:)
			echo "${r}Missing arguments. Exiting..${reset}"
			exit 1
			;;
	esac
done

if [[ ! -n $1  ]]; then
	echo "${r}Too less arguments.Exiting..${reset}"
	usage
	exit 1
fi

if [[ $generate -eq 1 ]] && [[ $jwt -eq 1 ]]; then
	echo "${g}Generating new symmetric key with ${b}$secret${reset}${g} on${reset} ${b}$jwttok${reset}${g} ${reset}"
	#genSymmetric $secret $jwttok
	gentester $jwttok
fi

if [[ $jwt -eq 1 ]] && [[ $wordlist -eq 1 ]]; then 
	echo "${g}Both jwt and wordlist activated${reset}"
	hashcatBrute $bruteFile $jwttok
fi 2>/dev/null

#if [[ $wordlist -eq 1 ]] || [[ $jwt -eq 1 ]]; then 
#	echo "Only one arg wordlist or jwt provided. Exiting"
#	exit 1
#fi

shift $((OPTIND-1))

if [[ $1 -ge 1 ]]; then
	echo "${r}Too many arguments.Exiting..${reset}"
	usage
	exit 1
fi
