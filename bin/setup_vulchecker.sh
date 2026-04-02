#!/bin/bash

apt install -y python3-pip wget

python3 -m pip install -U pip setuptools wheel
python3 -m pip install "Cython<3.0" cmake==3.11.10
python3 -m pip install ./structure2vec
python3 -m pip --no-cache-dir install ./VulChecker
python3 -m pip install "numpy<1.24"
