FROM ubuntu:20.04

WORKDIR /root

RUN apt-get update && apt-get install -y \
    git \
    python3-pip \
    wget \
    ninja-build

RUN mkdir epdg
WORKDIR epdg

RUN git clone --depth 1 https://github.com/ymirsky/VulChecker.git
RUN git clone --depth 1 https://github.com/gtri/structure2vec.git

RUN python3 -m pip install "Cython<3.0" cmake==3.31.10
RUN python3 -m pip install ./structure2vec
RUN python3 -m pip --no-cache-dir install ./VulChecker
RUN python3 -m pip install "numpy<1.24"
RUN python3 -m pip install pandas

RUN wget https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.0/llvm-project-10.0.0.tar.xz
RUN tar xvf llvm-project-10.0.0.tar.xz
RUN mv llvm-project-10.0.0 llvm-project

RUN git clone --depth 1 https://github.com/michaelbrownuc/llap.git llap-master
RUN cp -R llap-master/src/* llvm-project/llvm/lib/Transforms/

WORKDIR llvm-project/

RUN cmake -S ./llvm/ -B llvm-build -DCMAKE_BUILD_TYPE=Release
RUN make -C llvm-build -j 16
RUN make -C llvm-build install
RUN cmake -S ./clang/ -B clang-build -DCMAKE_BUILD_TYPE=Release
RUN make -C clang-build -j 16
RUN make -C clang-build install

ENV HECTOR_LIB=/root/epdg/llvm-project/llvm-build/lib
