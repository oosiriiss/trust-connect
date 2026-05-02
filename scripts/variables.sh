REPO_PATH=$(git rev-parse --show-toplevel)
BUILD_PATH="$REPO_PATH/build"
BUILD_COMMAND="cmake -B $BUILD_PATH -G Ninja -DCMAKE_BUILD_TYPE=Release"
COMPILE_COMMAND="cmake --build $BUILD_PATH --parallel --config Release"
CLIENT_EXE_CMD="cd $BUILD_PATH && $BUILD_PATH/client-app"
SERVER_EXE_CMD="cd $BUILD_PATH && $BUILD_PATH/server-app"
TTP_EXE_CMD="cd $BUILD_PATH && $BUILD_PATH/ttp-app"
TTP_CERT_PATH="$BUILD_PATH/ttp.cert"
