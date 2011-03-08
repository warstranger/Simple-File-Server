#!/bin/bash

declare DOC_DIR=doc
declare CSS_SCHEME=grayscale

cd `dirname "${0}"`

if [[ -d $DOC_DIR ]]; then
	echo -ne Remove old documentation ...
	rm -rf $DOC_DIR
	echo -e ' \033[32;1mdone\033[0m'
fi

echo -e Generate new documentation ...

epydoc -v --html -o $DOC_DIR -c $CSS_SCHEME \
-n 'Simple File Server' -u 'none' --parse-only --graph all \
*.py customlogging/

chmod go-rwx -R $DOC_DIR
