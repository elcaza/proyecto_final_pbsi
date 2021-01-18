#!/bin/bash
# Script para obtener las cabeceras de seguridad
# https://github.com/meliot/shcheck

# Usage: ./obtener_secure_headers.sh https://site.com

URL=$1
RESPONSE=$(python3 shcheck.py -d -j $URL)
echo $RESPONSE