#!/bin/bash

wget https://github.com/civetweb/civetweb/archive/refs/tags/v1.16.tar.gz
tar xf v1.16.tar.gz
rm v1.16.tar.gz
cd civetweb-1.16
make lib WITH_WEBSOCKET=1
mv libcivetweb.a ..
cd ..
rm -r civetweb-1.16

