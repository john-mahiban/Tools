#!/bin/bash
# Author -John Jeffrey Mahiban 
# About - This tool finds hash of a file (SHA1, SHA256, md5) 

hashcheck() {
    local file=$1
    local hashfunction=$2
    local hashval=""

    case "$hashfunction" in
        md5)
            hashval=$(md5sum "$file"  | awk '{ print $1 }')
            ;;
        sha1)
            hashval=$(sha1sum "$file"  | awk '{ print $1 }')
            ;;
        sha256)
            hashval=$(sha256sum "$file"  | awk '{ print $1 }')
            ;;
        *)
            echo "Unknown hash: '$hashfunction'. Supports only md5, sha1, & sha256."
            return 1
            ;;
    esac

    echo " The $hashfunction hash for file '$file': $hashval"
}


if [ "$#" -lt 2 ] || [ "$#" -gt 2 ];then
    echo
    echo " Usage info:"
    echo "  $0  <file_path>     <hash function>"
    echo
    echo "Accepted hash functions:"
    echo -e  "\tmd5\n\tsha-1\n\tsha-256"
    echo
    exit 1
fi

file="$1"
hashfunction="$2"

# Check if  file actually exists
if [ ! -f "$beconfile" ];  then
    echo " File '$file' can't be found."
    exit 2
fi

hashcheck "$file" "$hashfunction"
