# crackBTCwallet
Crack encrypted master Key and ckey of a bitcoin wallet. Just a  PROOF OF CONCEPT

mkey and ckeys are encrypted with AES256CBC

Well this is almost infeasible but Murphy's law say that:

>Anything that can possibly go wrong, does

in other words

>if something can happen, it will be happen

An AES key is an array of 32 bytes length this a chance of 1 of 2^256 This number have 78 decimal digits

>115792089237316195423570985008687907853269984665640564039457584007913129639936

When the correct key is found the code works proof of concept

![Proof of Concept](https://pbs.twimg.com/media/EmUnAflUcAAKDFl?format=png&name=large)

Today I can test around 150 Millions AES keys per second with Intel AESni instrucction with 4 threads on an Intel Xeon CPU E3-1271 v3 @ 3.60GHz

## How to use

first compile, to do it you need yasm.

```
sudo apt install yasm
```

after that only use make


```
make
```

execute

```
./crackbtcshell
```

now one wild shell appears
```
crackBTC >
```

Now you can load a ckey, set the number of threads, quiet the output and some others configs

```
crackBTC > set quiet 1
crackBTC > set threads 2
crackBTC > load ckey 2e24da42feb389aab372163cac88c5b9233d6f1a2e6bcb4e8337dfa21f0aa85309fa70c00637474a88b0d881c4d93155
crackBTC > start
```
Now yo can see the stats:

```
crackBTC > stats
AES256 block operations 85000000/s
crackBTC > stats
AES256 block operations 84848484/s
crackBTC > stats
AES256 block operations 84507042/s
```

exit with exit command or also Ctrl+C

```
crackBTC > exit
%
```

## Extract the Ckey and  Mkey

To extract the ckeys and the mkey you only need to pass the filename of your wallet as param of the get_mkey_ckey
```
./get_mkey_ckey wallet.dat
```

## Multiple ckeys and mkeys

You can multiply your chances of get one valid key if you load many ckeys and mkeys.

Only ONE ckey per wallet is needed because all the Ckeys of one wallet are encrypted with the same KEY.

```
crackBTC > set quiet 1
crackBTC > set threads 4
crackBTC > load ckey 2e24da42feb389aab372163cac88c5b9233d6f1a2e6bcb4e8337dfa21f0aa85309fa70c00637474a88b0d881c4d93155
crackBTC > load mkey 6638b43ae50d0e3d08d8e88928722b5768d8a172e7178fc67f587b4be5d6d22d5df78f23ca0a59d5d28c95d2b5d59dae
crackBTC > start
```

## load a file

Also you can load a file with the commands in it

commands.txt

```
set quiet 1
set threads 4
load ckey 2e24da42feb389aab372163cac88c5b9233d6f1a2e6bcb4e8337dfa21f0aa85309fa70c00637474a88b0d881c4d93155
load mkey 6638b43ae50d0e3d08d8e88928722b5768d8a172e7178fc67f587b4be5d6d22d5df78f23ca0a59d5d28c95d2b5d59dae
start
```

And then:

```
crackBTC > load file commands.txt
```

## Test by you own

If you have doubt about if this code works, you can test by you own. Firts you need to know what is the KEY of your own test wallet and then test it with the next command:


```
crackBTC > try key 563758754506d53828c5383d2cb6296efe7f217c5ef6a84b13bce3ecec66da2e
```

Output:
```
Posible Key found
key_material: 563758754506d53828c5383d2cb6296efe7f217c5ef6a84b13bce3ecec66da2e
For ckey or mkey: 2e24da42feb389aab372163cac88c5b9233d6f1a2e6bcb4e8337dfa21f0aa85309fa70c00637474a88b0d881c4d93155
```

## Getting the PrivKey in WIF format

Well if you have your AES KEY, now you can use it to Decrypt your Ckey.

first you need to calculate you IV for you current CKey:

```
crackBTC > doublesha256 0382ca08ce78b0935099c74db12873a7dc1cba10a44165ce8cc1d0602f49ee97f5
```

Output:
```
double sha256: 35fc5f8253f1bcf2c185571a35413f1f8a1816ee02360f36d0bd6339755f93f5
```

The IV are the first 32 hexchar of the given hash
IV: 35fc5f8253f1bcf2c185571a35413f1f

Now only decrypt the ckey:

```
crackBTC > aesdecrypt 35fc5f8253f1bcf2c185571a35413f1f 563758754506d53828c5383d2cb6296efe7f217c5ef6a84b13bce3ecec66da2e 2e24da42feb389aab372163cac88c5b9233d6f1a2e6bcb4e8337dfa21f0aa85309fa70c00637474a88b0d881c4d93155
```

Output:
```
decrypt_iv 35fc5f8253f1bcf2c185571a35413f1f
decrypt_key 563758754506d53828c5383d2cb6296efe7f217c5ef6a84b13bce3ecec66da2e
decrypt_enc 2e24da42feb389aab372163cac88c5b9233d6f1a2e6bcb4e8337dfa21f0aa85309fa70c00637474a88b0d881c4d93155
len: 48
Decrypted: 3ea5eaabe7f7b997ce732acc9cf08315a805109003ce2bd918bac1b73b82d7b710101010101010101010101010101010
```

## WIF

Just omit the sixteen "10" at the end of the decrypted ckey

BTW if you don't GET sixteen "10" at the end of the decrypted ckey something is Wrong with your inputs.


```
privatekeytowif 3ea5eaabe7f7b997ce732acc9cf08315a805109003ce2bd918bac1b73b82d7b7
```

Output:

```
Private KEY uncompressed 5JHsqscg3o1iAWjRP83nWWJFbgMrjnXwVQoxejtAqp4t6cCVgbo
Private KEY compressed KyKVQiQTML68gzEEce7HsEK9S4j4XqyZWQ6GdaGrSSk8XZJHqNWe
```

## Why this s**t is so complicated

Well, is not complicated but maybe this is not for you.

Kinds regards!
#### AlbertoBSD
