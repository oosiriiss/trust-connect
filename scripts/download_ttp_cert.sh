
CERT_OUT_DIR="${1:-./build}"
CERT_OUT_NAME="${2:-ttp.cert}"
CERT_OUT_FULL_PATH="$CERT_OUT_DIR/$CERT_OUT_NAME"
TTP_CONTAINER_NAME="ttp"

echo "Certificate output directory: $CERT_OUT_DIR"
echo "Certificate file name: $CERT_OUT_NAME"
echo "Certificate full path: $CERT_OUT_FULL_PATH"
echo "Ttp container name: $TTP_CONTAINER_NAME"

if ! [[ -d $CERT_OUT_DIR ]]; then
   echo "Certificate output directory ($CERT_OUT_DIR) is invalid"
   exit -1
fi

echo "---"

TTP_HEALTHCHECK_COMMAND="$(docker inspect -f {{.State.Health.Status}} $TTP_CONTAINER_NAME)"
echo "Checking if $TTP_CONTAINER_NAME container is healthy with command: '$TTP_HEALTHCHECK_COMMAND'"
if [ $TTP_HEALTHCHECK_COMMAND != "healthy" ]; then
   echo "$TTP_CONTAINER_NAME is not healthy. Couldn't download the certificate"
   exit -2
fi

echo "Healthy. Copying certificate to $CERT_OUT_FULL_PATH"
COPY_COMMAND="`docker cp $TTP_CONTAINER_NAME:/app/ttp.cert $CERT_OUT_FULL_PATH`"
