#!/bin/bash

INPUT="${1:-abl.img}"
OUTPUT="${2:-abl.bin}"

if [ "$#" -gt 2 ]; then
    echo "Usage: $0 [input_file] [output_file]"
    exit 1
fi

if [ ! -f "$INPUT" ]; then
    echo "Input file not found: $INPUT"
    exit 1
fi

offset=$(grep -oba 'ABL' "$INPUT" | head -n 1 | cut -d: -f1)
if [ -z "$offset" ]; then
    echo "ABL header not found in the input file."
    exit 1
fi

tail -c +"$((offset + 0xC00))" "$INPUT" > "$OUTPUT"

sha256sum "$OUTPUT"