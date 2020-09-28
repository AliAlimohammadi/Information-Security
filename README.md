# Cyber Security

This repository mainly consists of exploits in the form of `Python` scripts and a bunch of `PDF` documentation, indicating instructions and results. For instance, **E2E Messenger** implements the following schema:

Graphical demonstration of (a)symmetric encryption:
```mermaid
graph LR
A[Alice] -- Preshared Key --> B((AES))
B -- Preshared Key --> A
B -- Preshared Key --> D[Bob]
D -- Preshared Key --> B
A -- Bob's Public Key --> C(RSA)
C -- Bob's Private Key --> D
D -- Alice's Public Key --> C
C -- Alice's Private Key --> A
```