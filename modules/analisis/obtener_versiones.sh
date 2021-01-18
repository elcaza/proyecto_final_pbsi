#!/bin/bash
# Script para obtener las versiones de un sitio web

# Usage: ./obtener_versiones.sh https://www.site.com/
# Example: ./obtener_versiones.sh https://www.0php.com/

URL=$1

SERVER=$(curl -Iks $URL | grep -i Server)
POWERED_BY=$(curl -Iks $URL | grep -i x-powered-by)

echo $SERVER
echo $POWERED_BY
echo $?