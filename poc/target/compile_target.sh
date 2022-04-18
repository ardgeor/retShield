#!/bin/bash


function usage() {
	echo -e "usage: $0 <C file> <output_type> <arch_bits>"
	echo -e "output_type in {ASM, EXE}"
	echo -e "arch_bits in {32, 64}"
	exit 0
}

function exit_with_error() {
	echo -e "Error: ${1}"
	echo -e "Aborting..."
	exit 1
}

# Install 'gcc-multilib' package

if [ $# -lt 3 ]
then
	usage
fi

c_file="$1"
o_type="$2"
a_bits="$3"

if [ ! -f ${c_file}  ]
then
	exit_with_error "Input file does not exist: '$c_file'"
fi

suffix=$a_bits
asm_file="${c_file%.*}_${suffix}b.s"
exe_file="${c_file%.*}_${suffix}b"
comp_options="-g"
output=""

if [ "${o_type}" = "ASM" ]
then	
	comp_options="$comp_options -S"
	output="${asm_file}"
elif [ "${o_type}" = "EXE" ]
then	
	comp_options="$comp_options -fno-stack-protector -D_FORTIFY_SOURCE=0 -z norelro -z execstack"
	output="${exe_file}"
else
	exit_with_error "Invalid output type: ${o_type}"
fi

if [ "${a_bits}" = "32" ]
then
	comp_options="$comp_options -m32"
fi

echo -e "[*] Compiling target without protections..."
command="gcc $comp_options -o $output ${c_file}"
echo -e "\t $command"
eval "$command"

echo -e "    Target compiled"

if [ "${o_type}" = "EXE" ]
then
    echo -e "[*] Assigning ownership and permissions..."
    sudo chown root:root ${exe_file}
	sudo chmod u+s ${exe_file}
fi

echo -e "    Target ready"

exit 0
