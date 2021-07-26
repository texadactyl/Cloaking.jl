#!/usr/bin/bash

cat <<EOF | julia
import Pkg
Pkg.add(url = "https://github.com/texadactyl/Cloaking.jl")
EOF

