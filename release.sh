#! /bin/sh

if [ "$1EMPTY" = "EMPTY" ]; then
    echo "Usage: $0 DIRECTORY"
    exit 2
fi

folder="$1"

find $folder -mindepth 2 \
    \( -name 'Makefile' -o -name '*.rs' -o -name '*.txt' \) \
    -print0 | xargs -0 zip -9 dmitry-vasiliev-solutions-$folder.zip
