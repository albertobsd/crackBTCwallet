# crackBTCwallet
Crack encrypted master Key (AES 256 CBC with Padding)

Well this is almost infeasible but Murphy's law say that:

>Anything that can possibly go wrong, does

in other words

>if something can happen, it will be happen

An AES key is an array of 32 bytes length this a chance of 1 of 2^256 This number have 78 decimal digits

>115792089237316195423570985008687907853269984665640564039457584007913129639936

When the correct key is found the code works proof of concept

![Proof of Concept](https://pbs.twimg.com/media/EmUnAflUcAAKDFl?format=png&name=large)

Today I can test around 100 Millions AES keys per second with Intel AESni instrucction with 3 threads on an Intel Xeon CPU E3-1271 v3 @ 3.60GHz
