# Dependencies
- rysnc
- jq
- docker
- ~50GB of hardrive space
- pandas (python)

# Building the docker image
Everything should be run from the project root. To build the image run: `docker build -t cse713_epdg .`
This will take a while.

# Running the ePDG docker container
To run the container: `docker run --name epdg_container -d --rm --shm-size 2g -w /home/ubuntu -v $(pwd):/home/ubuntu/ -it cse713_epdg /bin/bash`

# Generating the PrimeVul testcases
First you must download the "primevul_data.tar.gz" from this google drive: https://drive.google.com/drive/folders/1By6IVmFA-i_FJi0cTawC7TlxtTt0u8Ld?usp=sharing
Then you must unpack the .tar.gz file in the project root.
To generate the testcases run: `./bin/extract_primevul_testcases -i <input-directory> -o <output-directory>`

# Generating the ePDGs
To generate the ePDGs run: `./bin/generate_epdgs.py -i <testcase-directory> -t <cmake-build-targets-file>` (for the cmake build target file you will point that at the "epdg_build_targets.json" which is extracted from the tar.gz file). This will take a while.

# Notes
- It is possible to have a connection issue when building the docker image. Just trying reruning the build.
- Many project fail building ePDG.
