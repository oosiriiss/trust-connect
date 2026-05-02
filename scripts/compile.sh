#!/bin/sh

source ./variables.sh

echo "Repository root path: $REPO_PATH";

cd $REPO_PATH

echo "Checking if ninja exists"
if ! (command -v ninja 2>&1 >> /dev/null); then
   echo "ninja command doesn't exist"
   exit -2
fi

echo "ninja found"
echo "Creating build configuration with: '$BUILD_COMMAND'"
eval $BUILD_COMMAND
echo "Compiling project."
eval $COMPILE_COMMAND
