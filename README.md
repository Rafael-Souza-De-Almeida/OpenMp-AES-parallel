# 🚀 OpenMp-AES-parallel  
### Paralelização do algoritmo AES usando OpenMP (projeto acadêmico)

![C](https://img.shields.io/badge/Language-C-blue)
![OpenMP](https://img.shields.io/badge/OpenMP-Enabled-yellow)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Proof_of_Concept-purple)

Este repositório contém uma implementação didática do **AES (Advanced Encryption Standard)** com suporte a experimentos de **paralelização via OpenMP**.  
O código é baseado no fork do projeto original de `dhuertas/AES` e foi adaptado para estudos de desempenho.

> ⚠️ **Atenção:**  
> Este código é voltado para aprendizado e experimentação.  
> Não deve ser utilizado em produção, pois implementações simples com tabelas de lookup podem ser vulneráveis a ataques por canais laterais (cache/timing).

---

## 📌 Objetivos do projeto

- Estudar o funcionamento interno do AES.
- Aplicar técnicas de paralelização com OpenMP.
- Medir speedup e desempenho criptografando múltiplos blocos.
- Criar uma base clara para relatórios e projetos universitários.

---

## 📁 Estrutura do Repositório

```
.
├── aes.c
├── aes.h
├── gmult.c
├── gmult.h
├── main.c
├── input.txt
├── output.aes
├── output_decrypted.txt
└── LICENSE
```

### 📄 Descrição dos principais arquivos

| Arquivo | Função |
|--------|--------|
| `aes.c` / `aes.h` | Implementação do AES (cipher e inverse cipher) |
| `gmult.c` / `gmult.h` | Multiplicação no campo finito GF(2⁸) |
| `main.c` | Arquivo principal com exemplo de uso |
| `input.txt` | Texto exemplo para criptografar |
| `output.aes` | Resultado criptografado |
| `output_decrypted.txt` | Descriptografia resultante |

---

## 🛠️ Como compilar

> ⚠️ **Atenção:**  
> Este repositório possui makefile, mas abaixo está descrita a compilação manualmente. 

### 🔹 Compilação simples (sem OpenMP)

```bash
gcc gmult.c aes.c main.c -o aes
```

### 🔹 Compilação com OpenMP

```bash
gcc -fopenmp gmult.c aes.c main.c -o aes_openmp
```

### 🔹 Execução

```bash
./aes
```

---

## 📘 Exemplo de saída

```
Plaintext message:
00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff

Ciphered message:
8e a2 b7 ca 51 67 45 bf ea fc 49 90 4b 49 60 89

Original message (after inv cipher):
00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
```

---

## ⚡ Sobre paralelização com OpenMP

Para processar vários blocos de 16 bytes em paralelo:

```c
#pragma omp parallel for
for (int i = 0; i < total_blocos; i++) {
    AES_cipher(&blocos[i]);
}
```


## 🤝 Contribuições

Contribuições são bem-vindas!

- Abra uma **issue**
- Sugira melhorias
- Envie pull requests

---

## 📄 Licença

Distribuído sob a licença **MIT**.  
Consulte o arquivo `LICENSE` para mais detalhes.

---

## ⭐ Se este repositório te ajudou

Considere deixar uma estrela ⭐ no GitHub!

## 👨‍💻 Autores

- **Davi Cardoso**  
  🔗 GitHub: [github.com/Davi-Cardos](https://github.com/Davi-Cardos)

- **Rafael Souza**  
  🔗 GitHub: [github.com/Rafael-Souza-De-Almeida](https://github.com/Rafael-Souza-De-Almeida)

- **Maxwell William**  
  🔗 GitHub: [github.com/maxwellseveriano](https://github.com/maxwellseveriano)

