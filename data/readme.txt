Test data:

- data.bin : plaintext  1024 random bytes -- $ head -c 1024b < /dev/urandom > data.bin
- enc0.bin : ciphertext 'data.bin'        -- $ morscrypta encrypt -i data.bin -o enc0.bin -p LoremIpsumFlyingPossum500
- enc1.bin : ciphertext 'data.bin'        -- $ morscrypta encrypt -i data.bin -o enc1.bin -k pub.pem

Test keys:

- prv.pem  : Private key       -- $ openssl genpkey -algorithm X25519 -out prv.pem
- pub.pem  : Public key        -- $ openssl pkey -in prv.pem -pubout -out pub.pem
