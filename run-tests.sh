#!/usr/bin/env bash

EXEC="./aes"
INPUT_DIR="inputs"
OUTPUT_DIR="outputs"
LOG="resultados.csv"
MESSAGE="Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed pharetra eget orci non luctus. Mauris vel lectus accumsan, pulvinar nulla a, facilisis lacus. Quisque malesuada nunc a justo tempor, eu finibus quam gravida. Morbi ultricies tincidunt risus. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia curae; Mauris condimentum risus sit amet est rutrum, vitae pretium tortor luctus. Aliquam facilisis ligula pharetra dui condimentum vehicula. Maecenas quis turpis nibh. Nulla tempor volutpat rutrum. Donec eget pulvinar neque, ut aliquam sem. Aliquam erat volutpat."

TAMANHOS=(50 100 500 1000)

THREADS=(1 2 4 6 8 10 12)

echo "entrada_MB,threads,tempo_t,tempo_c,tempo_d" > "$LOG"

for size in "${TAMANHOS[@]}"; do
    FILE="$INPUT_DIR/input_${size}Mb.txt"

    if [ ! -f "$FILE" ]; then
        echo "Criando $FILE ..."
        echo yes "$MESSAGE" | head -c ${size}M > "$FILE"
        yes "$MESSAGE" | head -c ${size}M > "$FILE"
    else
        echo "$FILE já existe — pulando"
    fi
done

for size in "${TAMANHOS[@]}"; do
    for th in "${THREADS[@]}"; do
        for j in {1..3}; do

            INPUT="$INPUT_DIR/input_${size}Mb.txt"
            #OUTPUT="$OUTPUT_DIR/output_${size}Mb_${th}t.aes"
            OUTPUT_ENC="$OUTPUT_DIR/output.aes"
            OUTPUT_DEC="$OUTPUT_DIR/output_decrypted.txt"

            echo "Rodando: ${size}MB com ${th} threads..."

            echo $EXEC "$th" "$INPUT" "$OUTPUT_ENC" "$OUTPUT_DEC"
            #TEMPO=$( ( time -p $EXEC "$th" "$INPUT" "$OUTPUT_ENC" "$OUTPUT_DEC") 2>&1 | grep real | awk '{print $2}' )
            OUTPUT=$(
                { time -p $EXEC "$th" "$INPUT" "$OUTPUT_ENC" "$OUTPUT_DEC"; } \
                2>&1
            )
            TEMPO_TOTAL=$(echo "$OUTPUT" | grep "^real" | awk '{print $2}')
            TEMPO_C=$(echo "$OUTPUT" | grep "Tempo Criptografia ECB" | awk '{print $4}')
            TEMPO_D=$(echo "$OUTPUT" | grep "Tempo Descriptografia ECB" | awk '{print $4}')

            echo "${size},${th},${TEMPO_TOTAL},${TEMPO_C},${TEMPO_D}" >> "$LOG"
        done
    done
done
